#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <mutex>
#include <vector>
#include <list>
#include <iterator>
#include <Windows.h>
#include "windivert.h"

// The test IP is the IP of https://www.google.com/
#define DEBUG_DST_IP "142.250.184.238"
// 10 ping requests without delayer:
/*
Pinging 142.250.184.238 with 32 bytes of data:
Reply from 142.250.184.238: bytes=32 time=39ms TTL=114
Reply from 142.250.184.238: bytes=32 time=29ms TTL=114
Reply from 142.250.184.238: bytes=32 time=33ms TTL=114
Reply from 142.250.184.238: bytes=32 time=28ms TTL=114
Reply from 142.250.184.238: bytes=32 time=33ms TTL=114
Reply from 142.250.184.238: bytes=32 time=30ms TTL=114
Reply from 142.250.184.238: bytes=32 time=32ms TTL=114
Reply from 142.250.184.238: bytes=32 time=29ms TTL=114
Reply from 142.250.184.238: bytes=32 time=30ms TTL=114
Reply from 142.250.184.238: bytes=32 time=32ms TTL=114

Ping statistics for 142.250.184.238:
	Packets: Sent = 10, Received = 10, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
	Minimum = 28ms, Maximum = 39ms, Average = 31ms
*/
// 10 ping requests with delayer:
/*
Pinging 142.250.184.238 with 32 bytes of data:
Reply from 142.250.184.238: bytes=32 time=280ms TTL=114
Reply from 142.250.184.238: bytes=32 time=295ms TTL=114
Reply from 142.250.184.238: bytes=32 time=294ms TTL=114
Reply from 142.250.184.238: bytes=32 time=294ms TTL=114
Reply from 142.250.184.238: bytes=32 time=293ms TTL=114
Reply from 142.250.184.238: bytes=32 time=296ms TTL=114
Reply from 142.250.184.238: bytes=32 time=296ms TTL=114
Reply from 142.250.184.238: bytes=32 time=286ms TTL=114
Reply from 142.250.184.238: bytes=32 time=298ms TTL=114
Reply from 142.250.184.238: bytes=32 time=293ms TTL=114

Ping statistics for 142.250.184.238:
	Packets: Sent = 10, Received = 10, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
	Minimum = 280ms, Maximum = 298ms, Average = 292ms
*/
// Average latency difference = 261ms
// Maximum latency difference = 270ms
// Minimum latency difference = 241ms

#define LOG_THREAD_ACTIVITY 0

#define PROMPT_BEFORE_EXIT 1

// How many milliseconds the input loop should sleep between checks.
#define INPUT_SLEEP_MS 50
// How many milliseconds the sender loop should sleep between checks.
#define SENDER_SLEEP_MS 10
// The expected maximum packet length.
#define MAX_PACKET_LENGTH 1500

#ifdef DEBUG_DST_IP
#define SET_FILTER(x) (std::string("outbound and remoteAddr == ") + std::string(DEBUG_DST_IP))
#else
#define SET_FILTER(x) ("outbound and localPort == " + std::to_string(x))
#endif

#if PROMPT_BEFORE_EXIT
#define PROMPT_CLOSE SYNC_COUT("Press enter to close the program."); std::cin.get();
#else
#define PROMPT_CLOSE
#endif

#define PROMPT_CONTINUE {SYNC_COUT("Press enter to continue."); std::cin.get();}

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
		// Unlock the write mutex.
		writeMutex.unlock();
		// Create a locked ostream object and return it.
		return locked_ostream();
	}

	void NewLine() {
		// Lock the write mutex.
		writeMutex.lock();
		// Write a new line to the standard output.
		std::cout << std::endl;
		// Unlock the write mutex.
		writeMutex.unlock();
	}
};

// This is a more thread-safe version of std::cout. The line should always be ended with std::endl;
synchronized_ostream sync_cout;

#define SYNC_COUT(x) sync_cout << x << std::endl

#define PRINT_TRACE(x) SYNC_COUT("[TRACE]: " << x)
#define PRINT_INFO(x) SYNC_COUT("[INFO]: " << x)
#define PRINT_ERROR(x) SYNC_COUT("[ERROR]: " << x)

#if LOG_THREAD_ACTIVITY
#define THREAD_TRACE_BASE(x) SYNC_COUT("[THREAD]" x)
#else
#define THREAD_TRACE_BASE(x)
#endif

#define RECV_TRACE(x) THREAD_TRACE_BASE("[RECEIVER]: " << x)
#define SEND_TRACE(x) THREAD_TRACE_BASE("[SENDER]: " << x)
#define LOG_TRACE(x) THREAD_TRACE_BASE("[LOGGER]: " << x)

#define SENDER_SLEEP_TIME std::chrono::milliseconds(SENDER_SLEEP_MS)

// Contains the void pointer to the packet, the packet length, and the packet address.
typedef std::tuple<PVOID, UINT, WINDIVERT_ADDRESS*> PACKET_DATA;
typedef std::chrono::time_point<std::chrono::steady_clock> TIME_DATA;
typedef std::pair<PACKET_DATA, TIME_DATA> PACKET_TIME_DATA;

class Delayer {
private:
	bool _initialized;

	HANDLE _winDivertHandle;
	std::mutex _handleMutex;

	std::chrono::milliseconds _latency;

	HANDLE _getHandle() {
		std::lock_guard<std::mutex> lock(_handleMutex);
		return _winDivertHandle;
	}

	bool _active;

	std::string _filter;

	// A list of elements containing the pointers to the packet data and the receive time.
	// The packet list is always sorted from oldest to newest,
	// since the most recent packets are appended to the end.
	std::list<PACKET_TIME_DATA> _packets;
	std::mutex _packetMutex;

	// Gets a vector of packets older than the latency.
	// The caller should lock the packet mutex.
	std::vector<PACKET_DATA> _getPackets() {
		SEND_TRACE("Getting packets...");
		TIME_DATA current_time = std::chrono::steady_clock::now();
		std::vector<PACKET_DATA> packets;
		// The packet list iterator.
		std::list<PACKET_TIME_DATA>::const_iterator elem = _packets.cbegin();
		// Iterate over the list.
		while (elem != _packets.end()) {
			// Check if the packet is older than the given latency.
			if (current_time - elem->second > _latency) {
				// If it is, add the packet to the vector.
				SEND_TRACE("Got packet older than the given latency. Setting data...");
				packets.emplace_back(elem->first);
				// Remove the element from the list.
				elem = _packets.erase(elem);
			}
			else {
				// If it isn't, return the list.
				// The rest of the packets in the list will all be newer because of the ordering of the packets.
				SEND_TRACE("Packet was " << std::chrono::duration_cast<std::chrono::milliseconds>(current_time - elem->second).count() << " ms old.");
				return packets;
			}
		}
		// Return the empty vector if no packets were found.
		return packets;
	}

	std::thread _receiverThread;
	std::thread _senderThread;

	bool _shouldDeactivate = false;
	std::mutex _activationStateMutex;

	unsigned int _receivedCount;
	int _bufferedCount;

	void _receiverLoop() {
		PRINT_TRACE("Receiver loop started...");
		UINT currentSize = MAX_PACKET_LENGTH;
		PVOID currentPacket;
		WINDIVERT_ADDRESS * currentAddress;
		UINT received;
		bool success = false;
		while (true) {
			RECV_TRACE("Checking activation state...");
			// Lock the activation state mutex for the duration of the deactivation check.
			{
				std::lock_guard<std::mutex> lock(_activationStateMutex);
				// Check that the delayer isn't deactivating.
				if (_shouldDeactivate) {
					// If it is, close the thread.
					PRINT_INFO("The receiver thread is closing.");
					return;
				}
			}
			// Create a buffer of the maximum encountered packet size so far.
			currentPacket = new byte[currentSize];
			RECV_TRACE("Created packet buffer at address " << currentPacket << ".");
			// Create a new WinDivert address.
			currentAddress = new WINDIVERT_ADDRESS;
			RECV_TRACE("Created address buffer at address " << currentAddress << ".");
			RECV_TRACE("Receiving next packet...");
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
					PRINT_INFO("Recalibrated packet size:\nOld size: " << currentSize << "\nNew size: " << received);
					currentSize = received;
					// Delete the old packet and address heap objects.
					delete currentPacket;
					delete currentAddress;
				}
				// Else if the error was ERROR_NO_DATA, close this thread and print the error.
				else if (error == ERROR_NO_DATA) {
					PRINT_ERROR("Encountered ERROR_NO_DATA, closing receiver thread.");
					return;
				}
				else {
					PRINT_ERROR("WinDivertRecv() failed with error code " << error << ". Closing the receiver thread.");
					return;
				}
			}
			RECV_TRACE("Received a packet successfully.");
			// Add the received packet to the packet list and increment the received packet counter.
			std::lock_guard<std::mutex> lock(_packetMutex);
			_packets.emplace_back(
				PACKET_DATA(currentPacket, received, currentAddress),
				std::chrono::steady_clock::now()
			);
			_receivedCount += 1;
			_bufferedCount += 1;
			RECV_TRACE("Added the packet to the send buffer and updated packet counts.");
		}
	}

	unsigned int _sentCount;

	void _senderLoop() {
		PRINT_TRACE("Sender loop started...");
		bool success = false;
		while (true) {
			SEND_TRACE("Locking packet mutex...");
			{ // This starts the block where the packet mutex is locked.
				std::lock_guard<std::mutex> lock(_packetMutex);
				// Get the packets to send.
				std::vector<PACKET_DATA> packets = _getPackets();
				SEND_TRACE("Got " << packets.size() << " packets to send.");
				// Loop through the packets and send each one.
				for (size_t i = 0; i < packets.size(); ++i) {
					SEND_TRACE("Sending the " << i << ". packet.");
					// Send the packet.
					success = WinDivertSend(
						_winDivertHandle, // The WinDivert handle.
						std::get<0>(packets[i]), // The pointer to the packet.
						std::get<1>(packets[i]), // The length of the packet.
						NULL, // The amount of bytes injected. NULL because this is not required.
						std::get<2>(packets[i]) // The address of the injected packet.
					);
					
					// Check errors.
					if (!success) {
						DWORD error = GetLastError();

						if (error = ERROR_INVALID_PARAMETER) {
							PRINT_ERROR("WinDivertSend() failed from an invalid parameter. Closing the sender thread.");
							return;
						}
						else {
							PRINT_ERROR("WinDivertSend() failed with error code " << error << ". Closing the sender thread.");
							return;
						}
					}

					SEND_TRACE("Packet sent successfully, deleting packet data.");

					// Delete the packet and address objects.
					delete std::get<0>(packets[i]);
					delete std::get<2>(packets[i]);

					// Update the packet counters.
					_sentCount += 1;
					_bufferedCount -= 1;

					SEND_TRACE("Packet data deleted and packet counters updated.");
				}
				SEND_TRACE("Unlocking packet mutex.");
			} // The packet mutex is unlocked here.
			// Lock the activation state mutex for the duration of the deactivation check.
			SEND_TRACE("Checking activation state.");
			{
				std::lock_guard<std::mutex> lock(_activationStateMutex);
				// Check that the delayer isn't deactivating.
				if (_shouldDeactivate) {
					// If it is, close the thread.
					PRINT_INFO("The sender thread is closing.");
					return;
				}
			}
			SEND_TRACE("Sleeping for the predefined time.");
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
					PRINT_TRACE("The logger wait function detected deactivation on " << i + 1 << ". cycle.");
					return false;
				}
			}
			// Wait for 50 milliseconds.
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
		return true;
	}

	std::thread _loggerThread;

	// Logs information every second when the delayer is active.
	void _loggingLoop() {
		PRINT_TRACE("Logging loop started...");
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
					PRINT_INFO("Received: " << received << ", sent: " << sent << ", buffered: " << buffered << ".");

				// If packets were lost, the received count is greater than the sent and buffer counts combined.
				else if (received > sent + buffered) {
					PRINT_ERROR("Packets lost: " << received - sent - buffered << "! Received: " << received << ", sent: " << sent << ", buffered: " << buffered << ".");
				}

				// Other abnormal cases.
				else {
					PRINT_ERROR("Abnormal values! Received: " << received << ", sent: " << sent << ", buffered: " << buffered << ".");
				}
			}
			// Wait for a second between logs.
			if (!logSleepSecond()) {
				// If the function returned false, terminate the thread.
				PRINT_INFO("The logger thread is closing.");
				return;
			}
		}
	}

	// Starts the receiver, sender, and logger threads.
	void _startThreads() {
		PRINT_TRACE("Starting receiver thread...");
		_receiverThread = std::thread(&Delayer::_receiverLoop, this);
		PRINT_TRACE("Starting sender thread...");
		_senderThread = std::thread(&Delayer::_senderLoop, this);
		PRINT_TRACE("Starting logger thread...");
		_loggerThread = std::thread(&Delayer::_loggingLoop, this);
	}

	// Sets the deactivation flag and joins the threads.
	void _closeThreads() {
		PRINT_TRACE("Closing threads...");
		PRINT_TRACE("Setting the deactivation flag...");
		// Set the deactivation flag.
		{
			std::lock_guard<std::mutex> lock(_activationStateMutex);
			_shouldDeactivate = true;
		}
		PRINT_TRACE("Deactivation flag set successfully, joining threads...");
		// Wait for the receiver, sender, and logger threads to close.
		_receiverThread.join();
		PRINT_TRACE("Receiver thread joined.");
		_senderThread.join();
		PRINT_TRACE("Sender thread joined.");
		_loggerThread.join();
		PRINT_TRACE("Logger thread joined.");
		PRINT_TRACE("Threads closed successfully.");
	}

public:
	Delayer() {
		_initialized = false;
	}

	void Init(int port, long long latency) {
		PRINT_TRACE("Initializing the delayer with port " << port << " and latency of " << latency << " ms.");
		_receivedCount = 0;
		_bufferedCount = 0;
		_sentCount = 0;
		_latency = std::chrono::milliseconds(latency);
		_active = false;
		// Create a filter that accepts outbound packets from the given local port.
		_filter = SET_FILTER(port);
		PRINT_TRACE("Set filter \"" << _filter << "\".");
		// Initialize the packet list.
		_packets = std::list<PACKET_TIME_DATA>();
		_initialized = true;
	}

	~Delayer() {
		PRINT_TRACE("Delayer destructor called.");
		if (_active) {
			PRINT_TRACE("Delayer was active, deactivating...");
			if (!Deactivate())
				PROMPT_CONTINUE
		}
	}

	bool Activate() {
		// Check that the delayer was initialized.
		if (!_initialized) {
			PRINT_ERROR("The delayer must be initialized with the Init(...) function before activation.");
			return false;
		}

		// Check that the delayer isn't already active.
		if (_active) {
			SYNC_COUT("The delayer is already active.");
			return false;
		}

		PRINT_TRACE("Opening a WinDivert handle.");

		// Get the WinDivert handle.
		_winDivertHandle = WinDivertOpen(_filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);

		// Check that the operation was successful.
		if (_winDivertHandle == INVALID_HANDLE_VALUE) {
			// Get the error code if not.
			DWORD error = GetLastError();

			// If the error is ERROR_ACCESS_DENIED, request administrator permissions.
			if (error == ERROR_ACCESS_DENIED) {
				PRINT_ERROR(
					"This program has to be run with administrator privileges "
					"since it has to install the WinDivert drivers."
				);
				return false;
			}

			PRINT_ERROR("WinDivertOpen() failed with error code " << error << ".");
			return false;
		}

		PRINT_TRACE("WinDivert handle opened successfully.");

		// Start the receiver and sender threads.
		_startThreads();

		PRINT_INFO("Delayer activated.");

		return true;
	}

	bool Deactivate() {
		// Check that the delayer was initialized.
		if (!_initialized) {
			PRINT_ERROR("The delayer must be initialized with the Init(...) function before deactivating.");
			return false;
		}

		// Check that the delayer isn't already deactivated.
		if (_active) {
			SYNC_COUT("The delayer is already deactivated.");
			return false;
		}

		// Close the threads.
		_closeThreads();

		PRINT_TRACE("Closing the WinDivert handle...");

		// Close the WinDivert handle.
		bool success = WinDivertClose(_winDivertHandle);

		// Check for errors.
		if (!success) {
			DWORD error = GetLastError();
			PRINT_ERROR("WinDivertClose() failed with error code " << error << ".");
			return false;
		}

		PRINT_TRACE("WinDivert handle closed successfully.");

		PRINT_INFO("Delayer deactivated.");

		return true;
	}
};

Delayer delayer;

#define INPUT_SLEEP_TIME std::chrono::milliseconds(INPUT_SLEEP_MS)

namespace ShortcutWaiter {
	// This should return true if the shortcut to activate the delayer is pressed.
	bool ShouldActivate() {
		return (GetKeyState('A') & 0x8000) && (GetKeyState('J') & 0x8000) && (GetKeyState('S') & 0x8000);
	}
	// This should return true if the shortcut to deactivate the delayer is pressed.
	bool ShouldDeactivate() {
		return (GetKeyState('A') & 0x8000) && (GetKeyState('J') & 0x8000) && (GetKeyState('D') & 0x8000);
	}

	bool ShouldActivateWrapper() {
		static bool lastState = false;
		bool currentState = ShouldActivate();
		if (currentState == lastState)
			return false;
		lastState = currentState;
		if (currentState)
			return true;
		return false;
	}
	bool ShouldDeactivateWrapper() {
		static bool lastState = false;
		bool currentState = ShouldDeactivate();
		if (currentState == lastState)
			return false;
		lastState = currentState;
		if (currentState)
			return true;
		return false;
	}

	void TestShortcuts() {
		if (ShouldActivateWrapper())
			delayer.Activate();
		else if (ShouldDeactivate())
			delayer.Deactivate();
	}

	void ShortcutLoop() {
		PRINT_TRACE("Keyboard input loop started.");
		while (true) {
			// Test whether or not one of the shortcuts is being pressed.
			TestShortcuts();
			// Sleep for the input sleep time between checks.
			std::this_thread::sleep_for(INPUT_SLEEP_TIME);
		}
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
				SYNC_COUT("Please enter a number that's greater than 0.");
		}
		else
			// If the parse was unsuccessful, prompt the user for an integer.
			SYNC_COUT("Please enter an integer.");
	}

	return input;
}

int main() {
	// Prompt the user for the port(s).
	int port = (int)PromptPositiveNum("Please enter the port the application uses to send network packets: ");
	long long latency = PromptPositiveNum("Please enter the desired latency (ms): ");

	// Initialize the delayer with the given port.
	delayer.Init(port, latency);

	// Create the shortcut checker thread.
	PRINT_TRACE("Starting the keybind checker thread.");
	std::thread shortcutThread(ShortcutWaiter::ShortcutLoop);

	PRINT_TRACE("Blocked main thread until the keyboard checker returns.");
	// Wait for the thread to finish.
	shortcutThread.join();
}