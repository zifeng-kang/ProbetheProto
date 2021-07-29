var sc = document.createElement('script');
sc.textContent = '(' + (function() {

	// Ref: https://developer.mozilla.org/en-US/docs/Web/API/Document/readyState
	console.log('Codes for showing loading time in ' + window.location.href);
	document.onreadystatechange = function () {
		if (document.readyState === 'complete') {
			// Ref: https://stackoverflow.com/questions/14341156/calculating-page-load-time-in-javascript
			var loadTime = window.performance.timing.domContentLoadedEventEnd- window.performance.timing.navigationStart;
			console.log('Loading time for ' + window.location.href + ' is: ' + loadTime);
		}
	}

}).toString() + ')()';
document.body.appendChild(sc);



