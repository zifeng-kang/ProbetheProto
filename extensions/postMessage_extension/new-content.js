console.log('postMessage Extension. ', window.location.href);
if (data_to_change[document.URL]) // this is msg_origin
{ 
	var sc = document.createElement('script');
	var msg_info_obj = data_to_change[document.URL]; // Obj { 'domain': {'url': Array[<receivers>], 'message':Array[<msg_str>]} * n }

	// Ref: https://developer.mozilla.org/en-US/docs/Web/API/Window/open#window_features

	sc.textContent = '(' + (function() {
		var msgs_info_buffer = msg_info_obj;
        msgs_info_buffer=Object.values(msgs_info_buffer);
		var sender_url = document.URL;
			window.onload = function() {
				var msg_array=[], msg_str, url_array=[], receiver, domain_element, windowObjectReference=null, idx_counter, postMessage_interval=2000;

                var outer_interval_ID = setInterval(function(){
                    if (!msgs_info_buffer.length && !url_array.length && !msg_array.length) {
                        windowObjectReference && windowObjectReference.close(); 
                        outer_interval_ID && clearInterval(outer_interval_ID);
                        return;
                    } 
                    // Preparation: msg_array is empty? url_array is empty? msgs_info_buffer is empty?
                    // assume url_array !== undefined
                    msg_array.length || (windowObjectReference && windowObjectReference.close(), 
                        url_array.length? (msg_array=domain_element['message'].slice(), receiver=url_array.shift()) : 
                            (domain_element=msgs_info_buffer.shift(), msg_array=domain_element['message'].slice(), 
                                url_array=domain_element['url'], receiver=url_array.shift()));
                    
                    // Avoid loading this extension on the new tab (same-origin postMessage)
                    (receiver===sender_url) && (receiver+='?__proto__[testk]=testv&__proto__.testk=testv&constructor[prototype][testk]=testv');
                    // Open tab and postMessage
                    (!windowObjectReference || windowObjectReference.closed) && (idx_counter=-5, windowObjectReference=window.open(receiver, "receiver"+idx_counter));
                    // Wait until idx_counter>=0
                    (idx_counter>=0) && (msg_str=msg_array.shift(), windowObjectReference.postMessage(msg_str, receiver), 
                        console.log('postMessage to ', receiver, ' MessageIs ', msg_str, ' SenderIs ', sender_url, ' MsgIdxIs ', idx_counter, ' EOS. '));
                    idx_counter+=1;
                }, postMessage_interval);
		}
	}).toString().replace('msg_info_obj', JSON.stringify(msg_info_obj)) + ')()';
	document.body.appendChild(sc);
}