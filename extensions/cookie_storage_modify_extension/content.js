console.log('Storage Modification Extension. ', window.location.href);
if (data_to_change[document.domain]) {
	console.log('Modifying cookie&storage into ', window.location.href);
	var date = new Date();
        date.setTime(date.getTime()+(24*60*60*1000));
        var expires = "; expires="+date.toGMTString();
	var cookie_to_change = data_to_change[document.domain]['cookie'] || '';
	for (let index in cookie_to_change) {
		cookie_to_change[index] += expires;
	}
	//cookie_to_change += expires;
	var local_to_change = data_to_change[document.domain]['localStorage'] || {};
	var session_to_change = data_to_change[document.domain]['sessionStorage'] || {};
	var sc = document.createElement('script');
sc.textContent = '(' + (function() {
	var logging = function() {
		var finding = {
        url: window.location.href,
        domain: document.domain
    };
    // add cookie type -1, localstorage type 1, sessionstorage type 0
    var cookie_archive = Array(), all_cookies = document.cookie.split('; '), cookie_i = all_cookies.length;
    while ( cookie_i-- ) {
        var component = all_cookies[cookie_i].split('=');
        component.push(-1);
        cookie_archive.push(component);
    }
    var local_archive = Array(), local_i = localStorage.length;
    while ( local_i-- ) {
        var local_component = Array(localStorage.key(local_i), localStorage.getItem( localStorage.key(local_i) ), 1);
        local_archive.push(local_component);
    }
    var session_archive = Array(), session_i = sessionStorage.length;
    while ( session_i-- ) {
        var session_component = Array(sessionStorage.key(session_i), sessionStorage.getItem( sessionStorage.key(session_i) ), 0);
        session_archive.push(session_component);
    }

    finding['storage'] = {"cookies": cookie_archive, "storage": local_archive.concat(session_archive)};
    console.log("LOGGING:" + JSON.stringify(finding));
	};
setTimeout(function() {
	// const data_to_change = require('./data.js');

	// Create session cookie with path=/current/page/ thus having more priority
	//document.cookie = "ookie_to_change";
	//
	var cookie_buffer = cookie_to_change;
	for (const element of cookie_buffer) {
		document.cookie = element;
	}

	var local_buffer = local_to_change;
	for (const [key, value] of Object.entries(local_buffer)) {
		localStorage.setItem(key, value);
	}
	var session_buffer = session_to_change;
        for (const [key2, value2] of Object.entries(session_buffer)) {
                sessionStorage.setItem(key2, value2);
        }
	logging();
	if( !localStorage.getItem('firstLoad') )
    {
      localStorage['firstLoad'] = true;
      window.location.reload();
    }
    else
      localStorage.removeItem('firstLoad');
}, 5000);
}).toString().replace('cookie_to_change', JSON.stringify(cookie_to_change)).replace('local_to_change', JSON.stringify(local_to_change)).replace('session_to_change', JSON.stringify(session_to_change)) + ')()';
document.body.appendChild(sc);
}
