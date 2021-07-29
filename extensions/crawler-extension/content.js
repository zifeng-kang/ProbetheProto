console.log("Executing link extraction");

var maxLinks = 10;

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

// Extract the root domain
// Added by zfk
// Ref: https://stackoverflow.com/questions/8498592/extract-hostname-name-from-string
function extractRootDomain(url) {
    // Input url should be just the hostname
    var domain = url, // extractHostname(url),
        splitArr = domain.split('.'),
        arrLen = splitArr.length;

    //extracting the root domain here
    //if there is a subdomain 
    if (arrLen > 2) {
        domain = splitArr[arrLen - 2] + '.' + splitArr[arrLen - 1];
        //check to see if it's using a Country Code Top Level Domain (ccTLD) (i.e. ".me.uk")
        if (splitArr[arrLen - 2].length == 2 && splitArr[arrLen - 1].length == 2) {
            //this is using a ccTLD
            domain = splitArr[arrLen - 3] + '.' + domain;
        }
    }
    return domain;
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

console.log("Setting interval ... ");
setInterval(function () {
    var links = [];
    do {
    	var aTags = document.getElementsByTagName("A");
    } while (!aTags);
    var localHostName = window.location.hostname;
    for (var i = 0; i < aTags.length; i++) {
        var aTag = aTags[i];
        try {
            var url = aTag.href;
            var urlDetails = getUrlDetails(url);
            // Only add links from the same domain and that are web pages
            // Modified by zfk
	    if (extractRootDomain(urlDetails.hostname) === extractRootDomain(localHostName) && isWebPage(url)) {
                links.push(url);
            }
        } catch (e) {
            console.log("failed to generate URL: " + e);
        }
    }
    if (!links) {
    	console.log("No subpages visited! " + localHostName);
	return;
    }
    links = getRandomSubarray(links);

    // Remove the '#' character, it was causing errors and doesn't change the actual url
    for (var j = 0; j < links.length; j++) {

	    links[j] = links[j].split("#")[0];
	    // by zfk: add query string for prototype-pollution detection
	    var strToFind = "?";
	    // Different patterns
	    var strToInsert = "KEY1[KEY2]=VALUE0"; // pattern1
	    //var strToInsert = "KEY0[KEY1][KEY2]=VALUE0"; // pattern2
	    //var strToInsert = "KEY0=VALUE0&KEY1=VALUE1&KEY2=VALUE2"; // pattern3
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
}, 2500);
