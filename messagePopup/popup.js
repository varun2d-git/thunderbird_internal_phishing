
async function load() {
  // The user clicked our button, get the active tab in the current window using
  // the tabs API.
  let tabs = await messenger.tabs.query({active: true, currentWindow: true});

  // Get the message currently displayed in the active tab, using the
  // messageDisplay API. Note: This needs the messagesRead permission.
  // The returned message is a MessageHeader object with the most relevant
  // information.
  let message = await messenger.messageDisplay.getDisplayedMessage(tabs[0].id);
  //let message2 = await messenger.messageDisplay.getDisplayedMessage(tabs[0]);

  //console.log('Checking message id');
  //console.log(tabs[0]);
  //console.log(tabs[0].id);
  console.log(messenger.accounts.list());
  const var_check = await messenger.accounts.list();
  //console.log('Var check');
  console.log(var_check);
  //console.log(var_check[0]['folders'][25]);
  //await messenger.messages.move([message.id], var_check[0]['folders'][25]);
  //await messenger.messages.update(message.id,{'junk':true});
  //await messenger.messages.archive([message.id]);




  // Update the HTML fields with the message subject and sender.
  document.getElementById("subject").textContent = message.subject;
  document.getElementById("from").textContent = message.author;

  // Request the full message to access its full set of headers.
  let full = await messenger.messages.getFull(message.id);
  let raw = await messenger.messages.getRaw(message.id);
  let urlRegex =/(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
  let matches = raw.match(urlRegex);

  document.getElementById("received").textContent = full.headers.received;
  //console.log('checking type of header variable');
  //console.log(typeof full.headers);
  //console.log(Object.keys(full.headers));


  console.log(full.headers['arc-authentication-results'][0].includes('spf=pass'));
  console.log("arc-authentication-results" in full.headers);
  let auth = "arc-authentication-results" in full.headers;
  let spf;
  let dkim;
  let dmarc;
  let spoofed;
  if ( auth == true) {
  console.log('inside auth flag creation loop');
  console.log(typeof full.headers['arc-authentication-results'][0].includes('spf=pass'));
  spf = full.headers['arc-authentication-results'][0].includes('spf=pass');
  dkim = full.headers['arc-authentication-results'][0].includes('dkim=pass');
  dmarc = full.headers['arc-authentication-results'][0].includes('dmarc=pass');
  spoofed = full.headers['arc-authentication-results'][0].includes('does not designate');
  }

  let myapikey ='AAABBBBccccccddddddaaaaa';
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


  if (matches !== null) {

        for (const [key, value] of Object.entries(matches)) {
            body['threatInfo']['threatEntries'].push({"url": value});
        }

  }

  console.log(body['threatInfo']['threatEntries']);
  const response = await fetch("https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+myapikey,
  //const response = await fetch("http://127.0.0.1:5000/bert_phishing",
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
                body: JSON.stringify(body) // body data type must match "Content-Type" header
                }
              ).then((response) => response.text());

  //document.getElementById("check").textContent = raw;
  //document.getElementById("check1").textContent = matches;
  //document.getElementById("check2").textContent =  body['threatInfo']['threatEntries'][1]['url'];
  document.getElementById("malurl").textContent = response;
  //contentType,partName,size,headers,parts  ;;Object.keys(full.parts)

  console.log(JSON.parse(response)['matches'].length);

  if (JSON.parse(response)['matches'].length > 1) {
  await messenger.messages.update(message.id,{'junk':true});
  await messenger.messages.move([message.id], { 'accountId': "account3", 'name': "Junk", 'path': "/Junk", 'subFolders': []});
  }

  if (auth == true) {
  if ((spf == false) || (dkim == false) || (dmarc == false) || (spoofed == true)) {
  console.log('inside auth loop');
  await messenger.messages.update(message.id,{'junk':true});
  await messenger.messages.move([message.id], { 'accountId': "account3", 'name': "Junk", 'path': "/Junk", 'subFolders': []});
        }
  }
}

document.addEventListener("DOMContentLoaded", load);
