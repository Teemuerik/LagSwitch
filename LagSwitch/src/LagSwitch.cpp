#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <mutex>
#include <vector>
#include <list>
#include "windivert.h"

#define PROMPT_BEFORE_EXIT 1

// How many milliseconds the input loop should sleep between checks.
#define INPUT_SLEEP_MS 50
// How many milliseconds the sender loop should sleep between checks.
#define SENDER_SLEEP_MS 10
// The expected maximum packet length.
#define MAX_PACKET_LENGTH 1500

#if PROMPT_BEFORE_EXIT
#define PROMPT_CLOSE sync_cout << "Press enter to close the program." << std::endl; std::cin.get();
#else
#define PROMPT_CLOSE
#endif

#define PROMPT_CONTINUE {sync_cout << "Press enter to continue." << std::endl; std::cin.get();}

long long TryStringToLongLong(const std::string & str, bool & success) {
	char* end;

	long long res = std::strtoll(str.c_str(), &end, 10);

	if (*end == '\0') {
		success = true;
		return res;
	}
	else {
		success = false;
		return 0;
	}
}

std::mutex writeMutex;

// This is the type of std::cout.
typedef std::basic_ostream<char, std::char_traits<char> > CoutType;
// This is the function signature of std::endl.
typedef CoutType& (*StandardEndLine)(CoutType&);

class locked_ostream {
public:
	template<typename T>
	const locked_ostream& operator<<(const T& rhs) const {
		// Delegate the operation to the std::cout stream.
		std::cout << rhs;
		// Return this instance by reference.
		return *this;
	}

	// Overload for std::endl;
	const locked_ostream& operator<<(StandardEndLine manipulator) const {
		// Call the manipulator with the standard output stream.
		manipulator(std::cout);
		// Unlock the write mutex.
		writeMutex.unlock();
		// Return this instance by reference.
		return *this;
	}
};

class synchronized_ostream {
public:
	template<typename T>
	const locked_ostream& operator<<(const T& rhs) const {
		// Lock the write mutex.
		writeMutex.lock();
		// Delegate the operation to the std::cout stream.
		std::cout << rhs;
		// Create a locked ostream object and return it.
		return locked_ostream();
	}

	// Overload for std::endl;
	const locked_ostream& operator<<(StandardEndLine manipulator) const {
		// Call the manipulator with the standard output stream.
		manipulator(std::cout);
		// Create a locked ostream object and return it.
		return locked_ostream();
	}
};

// This is a more thread-safe version of std::cout. The line should always be ended with std::endl;
synchronized_ostream sync_cout;

Delayer delayer;

#define INPUT_SLEEP_TIME std::chrono::milliseconds(INPUT_SLEEP_MS)

namespace ShortcutWaiter {
	// This should return true if the shortcut to activate the delayer is pressed.
	bool ShouldActivate() {
		static bool lastState = false;
	}
	// This should return true if the shortcut to deactivate the delayer is pressed.
	bool ShouldDeactivate() {
		static bool lastState = false;
	}

	// The least significant bit is 0 when no action is required.
	// If the least significant bit is 1, the second bit is 0 if the delayer should be deactivated and
	// 1 if the delayer should be activated.
	// The least significant bit is set to 0 by the delayer when the action is completed.
	short activationFlag = 0b00;

	// Prevents race conditions when accessing the activation flag.
	std::mutex activationMutex;

	void TestShortcuts() {
		if (ShouldActivate()) {
			// Lock the activation mutex for the duration of this scope.
			std::lock_guard<std::mutex> lock(activationMutex);

			// Check that the last action was completed.
			if (!(activationFlag & 0b01)) {
				// Check that the current state isn't active.
				if (activationFlag & 0b10) {
					// If it is, notify the user and return.
					sync_cout << "The delayer is already active." << std::endl;
					return;
				}

				else {
					// Otherwise activate the delayer.
					activationFlag = 0b11;
				}
			}

			else {
				// If it wasn't, check the state.
				if (activationFlag & 0b10) {
					// If the delayer is activating, notify the user and return.
					sync_cout << "The delayer is already being activated." << std::endl;
					return;
				}

				else {
					// Otherwise change the activation flag.
					activationFlag = 0b11;
				}
			}
		}

		else if (ShouldDeactivate()) {
			// Lock the activation mutex for the duration of this scope.
			std::lock_guard<std::mutex> lock(activationMutex);

			// Check that the last action was completed.
			if (!(activationFlag & 0b01)) {
				// Check that the current state isn't inactive.
				if (!(activationFlag & 0b10)) {
					// If it is, notify the user and return.
					sync_cout << "The delayer is already deactivated." << std::endl;
					return;
				}

				else {
					// Otherwise deactivate the delayer.
					activationFlag = 0b01;
				}
			}

			else {
				// If it wasn't, check the state.
				if (!(activationFlag & 0b10)) {
					// If the delayer is deactivating, notify the user and return.
					sync_cout << "The delayer is already being deactivated." << std::endl;
					return;
				}

				else {
					// Otherwise change the activation flag.
					activationFlag = 0b01;
				}
			}
		}
	}

	void ShortcutLoop() {
		// Test whether or not one of the shortcuts is being pressed.
		TestShortcuts();
		// Sleep for the input sleep time between checks.
		std::this_thread::sleep_for(INPUT_SLEEP_TIME);
	}
};

#define SENDER_SLEEP_TIME std::chrono::milliseconds(SENDER_SLEEP_MS)

typedef std::pair<PVOID, WINDIVERT_ADDRESS*> PACKET_DATA;
typedef std::chrono::time_point<std::chrono::steady_clock> TIME_DATA;
typedef std::pair<PACKET_DATA, TIME_DATA> PACKET_TIME_DATA;

class Delayer {
private:
	HANDLE _winDivertHandle;
	std::mutex _handleMutex;

	std::chrono::milliseconds _latency;

	HANDLE _getHandle() {
		std::lock_guard<std::mutex> lock(_handleMutex);
		return _winDivertHandle;
	}

	bool _active;

	const char * _filter;

	// A list of elements containing the pointers to the packet data and the receive time.
	std::list<PACKET_TIME_DATA> _packets;
	std::mutex _packetMutex;

	// Gets an array equal in size to the packet list,
	// only containing the packets received more than the given latency ago.
	// Returns the number of defined elements in the array.
	// Pass in a stack allocated empty array of packet data, equal in size to the packet list.
	// The caller should lock the packet mutex.
	size_t _getPackets(PACKET_DATA * packetArray) {
		TIME_DATA current_time = std::chrono::steady_clock::now();
		size_t count = 0;
		size_t packetIndex = 0;
		// The packet list is always sorted from oldest to newest,
		// since the most recent packets are appended to the end.
		for (PACKET_TIME_DATA elem : _packets) {
			// Check if the packet is older than the given latency.
			if (current_time - elem.second > _latency) {
				// If it is, add the packet to the packet array and remove the packet from the original list.
				packetArray[count] = elem.first;
				_packets.remove(elem);
				// Increment the array packet count.
				++count;
			}
			else {
				// If it isn't, return the array packet count.
				// The rest of the packets in the list will all be newer because of the ordering of the packets.
				return count;
			}
		}
	}

	std::thread _receiverThread;
	std::thread _senderThread;

	bool _shouldDeactivate = false;
	std::mutex _activationStateMutex;

	unsigned int _receivedCount;
	int _bufferedCount;

	void _receiverLoop() {
		UINT currentSize = MAX_PACKET_LENGTH;
		PVOID currentPacket;
		WINDIVERT_ADDRESS * currentAddress;
		UINT received;
		bool success = false;
		while (true) {
			// Lock the activation state mutex for the duration of the deactivation check.
			{
				std::lock_guard<std::mutex> lock(_activationStateMutex);
				// Check that the delayer isn't deactivating.
				if (_shouldDeactivate) {
					// If it is, close the thread.
					sync_cout << "The receiver thread is closing." << std::endl;
					return;
				}
			}
			// Create a buffer of the maximum encountered packet size so far.
			currentPacket = new byte[currentSize];
			// Create a new WinDivert address.
			currentAddress = new WINDIVERT_ADDRESS;
			// Receive the next packet in the queue.
			success = WinDivertRecv(
				_getHandle(),
				currentPacket,
				currentSize,
				&received,
				currentAddress
			);
			// Check for errors.
			if (!success) {
				DWORD error = GetLastError();
				// If the last error was ERROR_INSUFFICIENT_BUFFER,
				// set the current packet size to the received size and try again.
				if (error == ERROR_INSUFFICIENT_BUFFER) {
					sync_cout << "Recalibrated packet size:\nOld size: " << currentSize << "\nNew size: " << received << std::endl;
					currentSize = received;
					// Delete the old packet and address heap objects.
					delete currentPacket;
					delete currentAddress;
				}
				// Else if the error was ERROR_NO_DATA, close this thread and print the error.
				else if (error == ERROR_NO_DATA) {
					sync_cout << "Encountered ERROR_NO_DATA, closing receiver thread." << std::endl;
					return;
				}
				else {
					sync_cout << "WinDivertRecv() failed with error code " << error << ". Closing the receiver thread." << std::endl;
					return;
				}
			}
			// Add the received packet to the packet list and increment the received packet counter.
			std::lock_guard<std::mutex> lock(_packetMutex);
			_packets.emplace_back(PACKET_DATA(currentPacket, currentAddress), std::chrono::steady_clock::now());
			_receivedCount += 1;
			_bufferedCount += 1;
		}
	}

	unsigned int _sentCount;

	void _senderLoop() {
		while (true) {
			{
				std::lock_guard<std::mutex> lock(_packetMutex);

				// TODO: Send the packets.
				
				_sentCount += 1;
				_bufferedCount -= 1;
				// Lock the activation state mutex for the duration of the deactivation check.
				{
					std::lock_guard<std::mutex> lock(_activationStateMutex);
					// Check that the delayer isn't deactivating.
					if (_shouldDeactivate) {
						// If it is, close the thread.
						sync_cout << "The sender thread is closing." << std::endl;
						return;
					}
				}
			}
			// Sleep for the predefined amount before checking again.
			std::this_thread::sleep_for(SENDER_SLEEP_TIME);
		}
	}

	// Sleeps for a second and returns false if the thread should terminate.
	// Checks thread deactivation status every 50 ms (20 times).
	bool logSleepSecond() {
		for (int i = 0; i < 20; ++i) {
			{
				std::lock_guard<std::mutex> lock(_activationStateMutex);
				// Check that the delayer isn't deactivating.
				if (_shouldDeactivate) {
					// If it is, return false to close the thread.
					sync_cout << "The logger wait function detected deactivation on "
						<< i + 1 << ". cycle." << std::endl;
					return false;
				}
			}
			// Wait for 50 milliseconds.
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
		return true;
	}

	std::thread _loggingThread;

	// Logs information every second when the delayer is active.
	void _loggingLoop() {
		// The amount of received packets.
		unsigned int received;
		// The amount of sent packets.
		unsigned int sent;
		// The amount of packets in the buffer waiting to be sent.
		unsigned int buffered;
		while (true) {
			{
				{
					// Lock the packet mutex for the duration of this block.
					std::lock_guard<std::mutex> lock(_packetMutex);
					received = _receivedCount;
					_receivedCount = 0;
					sent = _sentCount;
					_sentCount = 0;
					buffered = _bufferedCount;
					_bufferedCount = 0;
				}

				// Log the data.
				// In a normal situation, received = sent + buffered.
				if (received == sent + buffered)
					sync_cout << "Received: " << received << ", sent: " << sent << ", buffered: " << buffered << "." << std::endl;

				// If packets were lost, the received count is greater than the sent and buffer counts combined.
				else if (received > sent + buffered) {
					sync_cout << "Packets lost: " << received - sent - buffered << "! Received: " << received << ", sent: " << sent << ", buffered: " << buffered << "." << std::endl;
				}

				// Other abnormal cases.
				else {
					sync_cout << "Abnormal values! Received: " << received << ", sent: " << sent << ", buffered: " << buffered << "." << std::endl;
				}
			}
			// Wait for a second between logs.
			if (!logSleepSecond()) {
				// If the function returned false, terminate the thread.
				sync_cout << "The logger thread is closing." << std::endl;
				return;
			}
		}
	}

	// Starts the receiver, sender, and logger threads.
	void _startThreads() {
		_receiverThread = std::thread(&Delayer::_receiverLoop, this);
		_senderThread = std::thread(&Delayer::_senderLoop, this);
		_loggingThread = std::thread(&Delayer::_loggingLoop, this);
	}

public:
	Delayer(int port, long long latency) {
		_receivedCount = 0;
		_bufferedCount = 0;
		_sentCount = 0;
		_latency = std::chrono::milliseconds(latency);
		_active = false;
		// Create a filter that accepts outbound packets from the given local port.
		_filter = ("outbound and localPort == " + std::to_string(port)).c_str();
		// Initialize the packet list.
		_packets = std::list<PACKET_TIME_DATA>();
	}

	~Delayer() {
		if (_active) {
			if (!Deactivate())
				PROMPT_CONTINUE
		}
	}

	bool Activate() {
		// Check that the delayer isn't already active.
		if (_active) {
			sync_cout << "The delayer is already active." << std::endl;
			return false;
		}

		// Get the WinDivert handle.
		_winDivertHandle = WinDivertOpen(_filter, WINDIVERT_LAYER_NETWORK, 0, 0);

		// Check that the operation was successful.
		if (_winDivertHandle == INVALID_HANDLE_VALUE) {
			// Get the error code if not.
			DWORD error = GetLastError();

			// If the error is ERROR_ACCESS_DENIED, request administrator permissions.
			if (error == ERROR_ACCESS_DENIED) {
				sync_cout <<
					"This program has to be run with administrator privileges "
					"since it has to install the WinDivert drivers."
					<< std::endl;
				return false;
			}

			sync_cout << "WinDivertOpen() failed with error code " << error << "." << std::endl;
			return false;
		}

		// Start the receiver and sender threads.
		_startThreads();

		return true;
	}

	bool Deactivate() {
		// Set the deactivation flag and wait for the receiver and sender threads to close.

		bool success = WinDivertClose(_winDivertHandle);

		if (!success) {
			DWORD error = GetLastError();
			sync_cout << "WinDivertClose() failed with error code " << error << "." << std::endl;
			return false;
		}

		return true;
	}
};

long long PromptPositiveNum(const char * message) {
	long long input;
	std::string inputString;

	// Loop until the user gives an input of the correct format (non-zero natural number).
	while (true) {
		sync_cout << message;

		// Get the user input.
		std::getline(std::cin, inputString);
		sync_cout << std::endl;

		bool success;
		// If the input string is empty, it is not a number.
		if (inputString == "")
			success = false;
		else
			// Try to parse the user input as an integer.
			input = TryStringToLongLong(inputString, success);

		if (success) {
			// If the parse was successful, test that the input number is greater than zero.
			if (input > 0)
				break;
			else
				sync_cout << "Please enter a number that's greater than 0." << std::endl;
		}
		else
			// If the parse was unsuccessful, prompt the user for an integer.
			sync_cout << "Please enter an integer." << std::endl;
	}

	return input;
}

int main() {
	// Prompt the user for the port(s).
	int port = PromptPositiveNum("Please enter the port the application uses to send network packets: ");
	long long latency = PromptPositiveNum("Please enter the desired latency (ms): ");

	// Create the delayer with the given port.
	delayer = Delayer(port, latency);

	// Create the shortcut checker thread.
	std::thread shortcutThread(ShortcutWaiter::ShortcutLoop);
}