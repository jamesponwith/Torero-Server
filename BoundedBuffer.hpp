#include <queue>
#include <condition_variable>
#include <mutex>
#include <thread>
/**
 * Class representing a buffer with a fixed capacity.
 */
class BoundedBuffer {
  public:
	  // public constructor
	  BoundedBuffer(int max_size);
	  
	  // public member functions (a.k.a. methods)
	  int getItem();
	  void putItem(int new_item);

  private:
	  // private member variables (i.e. fields)
	  int capacity;
	  std::queue<int> buffer;

	  // Extra stuff that we added 
	  std::condition_variable dataAvailable;
	  std::condition_variable spaceAvailable;
	  std::mutex m;

	  // This class doesn't have any, but we could also have private
	  // constructors and/or member functions here.
};
