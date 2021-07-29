console.log("Executing link extraction");

var maxLinks = 15;

// Generates a random sample from an array
function getRandomSubarray(arr, size) {
    // EC5 doesn't have default parameters
    if (typeof size === "undefined") {
        size = maxLinks;
    }

    if (arr.length < size) {
        size = arr.length;
    }

    var shuffled = arr.slice(0), i = arr.length, min = i - size, temp, index;
    while (i-- > min) {
        index = Math.floor((i + 1) * Math.random());
        temp = shuffled[index];
        shuffled[index] = shuffled[i];
        shuffled[i] = temp;
    }
    return shuffled.slice(min);
}

// Extracts the host from a URL
// Based on
function getUrlDetails(href) {
    var reURLInformation = new RegExp([
        '^(https?:)//', // protocol
        '(([^:/?#]*)(?::([0-9]+))?)', // host (hostname and port)
        '(/{0,1}[^?#]*)', // pathname
        '(\\?[^#]*|)', // search
        '(#.*|)$' // hash
    ].join(''));
    var match = href.match(reURLInformation);
    return match && {
        href: href,
        protocol: match[1],
        host: match[2],
        hostname: match[3],
        port: match[4],
        pathname: match[5],
        search: match[6],
        hash: match[7]
    }
}

// Detects whether a URL is a web page (instead of something like a PDF or an image)
// Based on https://stackoverflow.com/questions/6997262/how-to-pull-url-file-extension-out-of-url-string-using-javascript
function isWebPage(url) {
    // Remove everything to the last slash in URL
    url = url.substr(1 + url.lastIndexOf("/"));

    // Break URL at ? and take first part (file name, extension)
    url = url.split('?')[0];

    // Sometimes URL doesn't have ? but #, so we should also do the same for #
    url = url.split('#')[0];

    // Now we have only the file name
    var fileExt = url.split('.').pop();
    var acceptableExtensions = ["html", "php", "asp"];
    if (acceptableExtensions.indexOf(fileExt) !== -1) return true; // Check for allowed extension types
    if (fileExt.length === url.length) return true; // Files without an extension
    // All else
    return false;
}

console.log("Setting timeout");
setTimeout(function () {
    // by zfk: starting from original url
    var links = [window.location.href];
    var aTags = document.getElementsByTagName("A");
    var localHostName = window.location.hostname;
    for (var i = 0; i < aTags.length; i++) {
        var aTag = aTags[i];
        try {
            var url = aTag.href;
            var urlDetails = getUrlDetails(url);
            // Only add links from the same domain and that are web pages
            if (urlDetails.hostname === localHostName && isWebPage(url)) {
                links.push(url);
            }
        } catch (e) {
            console.log("failed to generate URL");
        }
    }
    links = getRandomSubarray(links);

    // Remove the '#' character, it was causing errors and doesn't change the actual url
    for (var j = 0; j < links.length; j++) {

	    links[j] = links[j].split("#")[0];
	    // by zfk: add query string for prototype-pollution detection
	    var strToFind = "?";
	    // according to vulnerable_pp_patterns.txt
	    // var strToInsert = "__proto__.testk=testv";
	    var strToInsert = "__proto__[testk]=testv&__proto__.testk=testv&constructor[prototype][testk]=testv";
	    // var strToInsert = "constructor[prototype][testk]=testv";
	    var n = links[j].indexOf(strToFind);
    	    if (n < 0) { // No strToFind found
		    if (links[j].endsWith('/')) {
			    links[j] = links[j] + strToFind + strToInsert;
		    }
		    else {
			    links[j] = links[j] + '/' + strToFind + strToInsert;
		    } 
	    }
	    else {
		    links[j] = links[j].substring(0,n+1) + strToInsert + '&' + links[j].substring(n+1);
	    }
    	    //return strToSearch.substring(0,n) + strToInsert + strToSearch.substring(n);
    }

    // Send message to background script to see if we should open the pages (based on depth)
    chrome.runtime.sendMessage({links: links}, function (response) {
        var link = response.link;
        if (link !== null) {
            window.location = link;
        }
    })
}, 8000);
