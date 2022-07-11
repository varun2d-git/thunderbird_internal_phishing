async function load() {
  // The user clicked our button, get the active tab in the current window using
  // the tabs API.
  let tabs = await messenger.tabs.query({active: true, currentWindow: true});

  // Get the message currently displayed in the active tab, using the
  // messageDisplay API. Note: This needs the messagesRead permission.
  // The returned message is a MessageHeader object with the most relevant
  // information.
  let message = await messenger.messageDisplay.getDisplayedMessage(tabs[0].id);

  // Update the HTML fields with the message subject and sender.
  document.getElementById("subject").textContent = message.subject;
  document.getElementById("from").textContent = message.author;
  
  // Request the full message to access its full set of headers.
  let full = await messenger.messages.getFull(message.id);
  let raw = await messenger.messages.getRaw(message.id);
  let urlRegex =/(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
  let matches = raw.match(urlRegex);

  document.getElementById("received").textContent = full.headers.received;
  let myapikey ='AAAAAAAaaaaaaaBBBBBbbbb';
  let body = {
                "client": {
                                "clientId": "testing",
                                "clientVersion": "0.0.1"
                          },
                "threatInfo": {
                                "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","MALICIOUS_BINARY"],
                                "platformTypes": ["ANY_PLATFORM"],
                                "threatEntryTypes": ["URL"],
                                "threatEntries": [
                                                    {"url": "https://testsafebrowsing.appspot.com/s/malware.html"}
                                                 ]
                               }
            };

  const response = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+myapikey,
                {
                method: 'POST', // *GET, POST, PUT, DELETE, etc.
                mode: 'cors', // no-cors, *cors, same-origin
                cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
                credentials: 'same-origin', // include, *same-origin, omit
                headers: {
                  'Content-Type': 'application/json'
                  //'Content-Type': 'application/x-www-form-urlencoded',
                },
                redirect: 'follow', // manual, *follow, error
                referrerPolicy: 'no-referrer', // no-referrer, *no-referrer-when-downgrade, origin, origin-when-cross-origin, same-origin, strict-origin, strict-origin-when-cross-origin, unsafe-url
                body: body // body data type must match "Content-Type" header
                }
              );

  document.getElementById("check1").textContent = Object.keys(matches);
  document.getElementById("check2").textContent = typeof matches;
  document.getElementById("check3").textContent = Object.keys(response);
  //contentType,partName,size,headers,parts  ;;Object.keys(full.parts)
}

document.addEventListener("DOMContentLoaded", load);
