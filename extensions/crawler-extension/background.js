var maxDepth = 10;
var tabs = {}; // Keeps track of links to be accessed
var allTabs = {}; // Keeps track of all links added to avoid repetition even after dequeue
var curDepths = {}; // Keeps track of the currently visited link's depth

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse) {
    var tabId = sender.tab.id;
    if (!tabs.hasOwnProperty(tabId)) {
        tabs[tabId] = new Queue();
        allTabs[tabId] = [];
        curDepths[tabId] = 0;
    }

    // Store the links one level deeper only if not at max depth
    if (curDepths[tabId] <= maxDepth) {
        var newDepth = curDepths[tabId] + 1;
        for (var i = 0; i < request.links.length; i++) {
            var link = request.links[i];
            // Only add if never visited
            if (allTabs[tabId].indexOf(link) === -1) {
                tabs[tabId].enqueue([link, newDepth]);
                allTabs[tabId].push(link);
            }
        }
    }

    // Open next link in the queue and update current depth
    var nextLink = null;
    if (!tabs[tabId].isEmpty()) {
        var item = tabs[tabId].dequeue();
        nextLink = item[0];
        curDepths[tabId] = item[1];
    }

    if (nextLink) { // added by zfk
	console.log("Now try visiting this link " + nextLink);
	// console.log(tabs[tabId]);
    	console.log("Current depth is " + curDepths[tabId]);
    }
    sendResponse({link: nextLink});
});
