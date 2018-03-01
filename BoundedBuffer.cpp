#include <cstdio>

#include "BoundedBuffer.hpp"

/**
 * Constructor that sets capacity to the given value. The buffer itself is
 * initialized to en empty queue.
 *
 * @param max_size The desired capacity for the buffer.
 */
BoundedBuffer::BoundedBuffer(int max_size) {
	capacity = max_size;
	// buffer field implicitly has its default (no-arg) constructor called.
	// This means we have a new buffer with no items in it.
}

/**
 * Gets the first item from the buffer then removes it.
 */
int BoundedBuffer::getItem() 
{
	std::unique_lock<std::mutex> lk(m); // Create unique lock, auto locks
	while (buffer.empty())
	{
		dataAvailable.wait(lk);	
	}
	int item = buffer.front();
	buffer.pop();
	spaceAvailable.notify_one();
	lk.unlock();
	return item;
}

/**
 * Adds a new item to the back of the buffer.
 *
 * @param new_item The item to put in the buffer.
 */
void BoundedBuffer::putItem(int new_item) 
{
	std::unique_lock<std::mutex> lock(m); // Create unique lock, auto locks
	while((int)buffer.size() == capacity)
	{
		spaceAvailable.wait(lock);
	}
	buffer.push(new_item);
	dataAvailable.notify_one();
	lock.unlock();
}
