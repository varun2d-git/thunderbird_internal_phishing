async function load() {

messenger.messages.onNewMailReceived.addListener(async (folder, messages) => {
    // Do something with folder and messages.
    //folder.name
    //message
    //console.log('checking values point 1');
    //console.log(Object.keys(messages.messages));
    //console.log(messages.messages[0]);
    let full = await messenger.messages.getFull(messages.messages[0].id);
    let raw = await messenger.messages.getRaw(messages.messages[0].id);
    let urlRegex =/(\b(https?|ftp|file):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|])/ig;
    let matches = raw.match(urlRegex);

    let myapikey ='ABCDabcdabcdABCD';

    let auth = "arc-authentication-results" in full.headers;
    let spf;
    let dkim;
    let dmarc;
    let spoofed;
    let detection = 'None';
    if ( auth == true) {
    console.log('Extracting authentication results from email header');

    spf = full.headers['arc-authentication-results'][0].includes('spf=pass');
    dkim = full.headers['arc-authentication-results'][0].includes('dkim=pass');
    dmarc = full.headers['arc-authentication-results'][0].includes('dmarc=pass');
    spoofed = full.headers['arc-authentication-results'][0].includes('does not designate');
    if (spf == true) {console.log('SPF check: Pass');} else {console.log('SPF check: Fail')};
    if (dkim == true) {console.log('dkim check: Pass');} else {console.log('dkim check: Fail')};
    if (dmarc == true) {console.log('dmarc check: Pass');} else {console.log('dmarc check: Fail')};
    if (spoofed == false) {console.log('spoofed check: Pass');} else {console.log('spoofed check: Fail')};

    }

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

    };
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

  console.log(JSON.parse(response)['matches'].length);

  if (JSON.parse(response)['matches'].length > 1) {
  console.log('Malicious url detected');
  console.log(response);

  detection = 'Malicious url, '+ response;
  //console.log(detection);
  await messenger.messages.update(messages.messages[0].id,{'junk':true});
  await messenger.messages.move([messages.messages[0].id], { 'accountId': "account4", 'name': "Junk", 'path': "/Junk", 'subFolders': []});
  };

  if (auth == true) {
  if ((spf == false) || (dkim == false) || (dmarc == false) || (spoofed == true)) {
  console.log('SPF / DKIM / DMACR / SPOOFED flag detected');
  console.log(full.headers['arc-authentication-results']);
  console.log(typeof full.headers['arc-authentication-results']);
  detection = 'Email header fail,' + full.headers['arc-authentication-results'].toString();
  await messenger.messages.update(messages.messages[0].id,{'junk':true});
  await messenger.messages.move([messages.messages[0].id], { 'accountId': "account4", 'name': "Junk", 'path': "/Junk", 'subFolders': []});
  
        }
  };


  console.log('Into message logging');
  let { messageLog } = await messenger.storage.local.get({ messageLog: [] });
  console.log(messageLog);
  messageLog.push({
                time: Date.now(),
                detection: detection
            });
  await messenger.storage.local.set({ messageLog });
  

  console.log('Analysis completed!');

})

}

document.addEventListener("DOMContentLoaded", load);
