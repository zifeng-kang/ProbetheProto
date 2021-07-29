console.log('Logging cookie&storage into ', window.location.href);
var sc = document.createElement('script');
sc.textContent = '(' + (function() {
setTimeout( function() {
    var finding = {
        url: document.URL,
        domain: document.domain, 
        referrer: document.referrer
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
}, 6500);
}).toString() + ')()';
document.body.appendChild(sc);


