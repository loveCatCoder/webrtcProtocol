/*
 *  Copyright (c) 2015 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */

'use strict';


var startIceButton = document.getElementById('start-ice-button');
startIceButton.addEventListener("click", startIce);

var websocketConn = null;
var webrtcConn = null;

function startIce() {

    //init peerconnection
    var servers = null;
    webrtcConn = new RTCPeerConnection(servers);
    webrtcConn.onicecandidate = gotIceCandidate;


    var url = 'http://127.0.0.1:7788/serversdp';
    var data = { username: 'example' };


    fetch(url, {
        method: 'POST', // or 'PUT'
        body: JSON.stringify(data), // data can be `string` or {object}!
        headers: new Headers({
            'Content-Type': 'application/json'
        }),
        mode: 'cors'
    }).then(res => res.json())
        .catch(error => console.error('Error:', error))
        .then(function (response) {
            
            var serverSdp =response.sdp;
            console.log(serverSdp)
            if(serverSdp){
                var desc = new RTCSessionDescription();
                desc.sdp = serverSdp;
                desc.type = 'offer';
                webrtcConn.setRemoteDescription(desc);
                // Since the 'remote' side has no media stream we need
                // to pass in the right constraints in order for it to
                // accept the incoming offer of audio and video.
                webrtcConn.createAnswer().then(
                    sendClientSdp,
                    onCreateSessionDescriptionError
                );
            }
        });

   
}

function onCreateSessionDescriptionError(error) {
    trace('Failed to create session description: ' + error.toString());

}
function onSetLocalDescriptionError(error) {
    trace('Failed to set setLocalDescription: ' + error.toString());

}

function onSetLocalDescriptionSuccess() {
    trace('localDescription success.');
}

function sendClientSdp(desc) {
    webrtcConn.setLocalDescription(desc).then(
        onSetLocalDescriptionSuccess,
        onSetLocalDescriptionError
    );
    console.log('local sdp: ' + desc.sdp);

    var url = 'http://127.0.0.1:7788/clientsdp';
    var data = { sdp: desc.sdp };

    fetch(url, {
        method: 'POST', // or 'PUT'
        body: JSON.stringify(data), // data can be `string` or {object}!
        headers: new Headers({
            'Content-Type': 'application/json'
        }),
        mode: 'cors'
    }).then(res => res.json())
        .catch(error => console.error('Error:', error))
        .then(response => console.log(response));
}


function gotIceCandidate(event) {
    if (event.candidate) {
        var url = 'http://127.0.0.1:7788/candidate';
        var data = { candidate: event.candidate };
    
        fetch(url, {
            method: 'POST', // or 'PUT'
            body: JSON.stringify(data), // data can be `string` or {object}!
            headers: new Headers({
                'Content-Type': 'application/json'
            }),
            mode: 'cors'
        }).then(res => res.json())
            .catch(error => console.error('Error:', error))
            .then(response => console.log(response));
    }
    else {
        // All ICE candidates have been sent
        console.log("got ice candidate is empty");
    }
}
