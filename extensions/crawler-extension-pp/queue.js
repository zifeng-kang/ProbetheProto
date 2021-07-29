// Based on https://www.geeksforgeeks.org/implementation-queue-javascript/
// Converted to pre-ES6 notation

function Queue() {
    this.items = [];
}

Queue.prototype.enqueue = function(element) {
    // adding element to the queue
    this.items.push(element);
};

Queue.prototype.dequeue = function() {
    // removing element from the queue
    // returns underflow when called on empty queue
    if (this.isEmpty())
        return "Underflow";
    return this.items.shift();
};

Queue.prototype.front = function() {
    // returns the Front element of the queue without removing it.
    if (this.isEmpty())
        return "No elements in Queue";
    return this.items[0];
};

Queue.prototype.isEmpty = function() {
    // return true if the queue is empty.
    return this.items.length === 0;
};

Queue.prototype.printQueue = function() {
    var str = "";
    for (var i = 0; i < this.items.length; i++)
        str += this.items[i] +" ";
    return str;
};