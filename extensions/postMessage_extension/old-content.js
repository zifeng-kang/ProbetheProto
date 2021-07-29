console.log('postMessage Extension. ', window.location.href);
// var this_name = window.location.href;
if (data_to_change[document.URL]) // this is msg_origin
{ 
	// console.log('postMessage to ', this_name);
	var sc = document.createElement('script');
	var msg_info_dict = data_to_change[document.URL]; // Array ( Array ( <receiver>, Array ( messages ) ) )

	// Ref: https://developer.mozilla.org/en-US/docs/Web/API/Window/open#window_features

	sc.textContent = '(' + (function() {

		// var windowObjectReference = null; // global variable
		var msgs_info_buffer = msg_info_dict;
			window.onload = function() {
				// var this_name = window.location.href;
				var windowObjectReference_Array = Array(msgs_info_buffer.length);
				// loop over the Array
				Object.entries(msgs_info_buffer).forEach(function(element, idx){
					setTimeout(function(){
						let receiver = element[0];
						windowObjectReference_Array[idx] = window.open(receiver, "receiver"+idx);
						// windowObjectReference = windowObjectReference_Array[idx];
						// if(!windowObjectReference || windowObjectReference.closed)
						// /* if the pointer to the window object in memory does not exist
						// 	or if such pointer exists but the window was closed */

						// 	{
						// 	// Open the vulnerable website to postMessage to
						// 	// Should set browser settings as always allowing popups
						// 		windowObjectReference = window.open(receiver, "receiver");
								
						// 	}
						element[1].forEach(function(msg_str){
							setTimeout(function(){ 
								if (windowObjectReference_Array[idx]) {
									windowObjectReference_Array[idx].postMessage(msg_str, receiver);
									console.log('postMessage to ', receiver, ' MessageIs ', msg_str);
								}
								}, 4000); // leave enough response time
						});
						setTimeout(function(){
							if (windowObjectReference_Array[idx]) {
								windowObjectReference_Array[idx].close();
							}
						}, 6000*element[1].length);

					}, idx*6000*element[1].length);	
					});
		}
	}).toString().replace('msg_info_dict', JSON.stringify(msg_info_dict)) + ')()';
	document.body.appendChild(sc);
}


