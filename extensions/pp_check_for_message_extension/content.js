console.log('pp Checking for obj, div, iframe in ', window.location.href);
var sc = document.createElement('script');
sc.textContent = '(' + (function() {
setTimeout(
	function() {
		var iframe = document.createElement('iframe'), div = document.createElement('div'), obj = {};
		var elem_array_to_check = [
			[obj, 'obj'], 
			[div, 'div'], 
			[iframe, 'iframe']
		];
		console.log('pp checking in processing ... ');
		elem_array_to_check.forEach(function(elem){
			let aaaa = elem[0];
			for (var key in aaaa) {
				if (key.includes('testk') && aaaa[key].includes('testv')){
					console.log('ppExploitFOUND keyIs: ' + key + ' valueIs: ' + aaaa[key] + ' __proto__ of: ' + elem[1] + ' href: ' + document.location.href);
					break;
				}
				// TODO: Add checking for cookies
			}
		});
		
	}
	, 10500); // should be smaller than the time set in crawler-extension/content.js

}).toString() + ')()';
document.body.appendChild(sc);

//document.write('<script>' + pp.toString() + ';pp();</script>')
//window.onload = pp
//pp();


