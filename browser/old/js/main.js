/*
 *  Copyright (c) 2015 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree.
 */

'use strict';


var webrtcStream = document.getElementById('webrtc-stream');

var serverAddress = document.getElementById('server-address');
var deviceId = document.getElementById('device-id');
var startTime = document.getElementById("start-time");


var playRealtimeButton = document.getElementById('play-realtime-button');
var teardownRealtimeButton = document.getElementById('teardown-realtime-button');

var readIndexButton = document.getElementById("read-index-button");
var playRecordButton = document.getElementById('play-record-button');
var pauseRecordButton = document.getElementById('pause-record-button');
var teardownRecordButton = document.getElementById('teardown-record-button');

var timeIndexList = document.getElementById("time-index");

var scaleInput = document.getElementById("scale-input");


var m_playmode = "";

playRealtimeButton.addEventListener("click", startRealtime);
teardownRealtimeButton.addEventListener('click', tearDown);

readIndexButton.addEventListener('click', readIndex);
playRecordButton.addEventListener('click', startRecord);
pauseRecordButton.addEventListener('click', pauseRecord);
teardownRecordButton.addEventListener('click', tearDown);

var websocketConn = null;
var webrtcConn = null;

var currentclick = ""
var connFlag = false;
var recordPauseFlag = false;

function readIndex() {

    currentclick = "read-index";
    if (websocketConn&&websocketConn.readyState == WebSocket.OPEN) {
        var req = new Object();
        req.type = "GET_RECORD_INDEX";
        req.deviceId = deviceId.value;
        req.startTime = "2021-1-1T12:00";
        req.endTime = "2022-1-1T12:00";
        req.channelId = "0";

        console.log("start");
        websocketConn.send(JSON.stringify(req));
    }
    else
    {
        connect();
    }

}

function startRecord() {
    currentclick = "play-record";
    
    if(connFlag == true)
    {
        playRecord();
        console.log("start record :connFlag ");
        return;
    }
    if (websocketConn&&websocketConn.readyState == WebSocket.OPEN) {
        console.log("start record :describe ");
        var servers = null;
        webrtcConn = new RTCPeerConnection(servers);
        trace('Created peer connection');
        webrtcConn.onicecandidate = gotIceCandidate;
        webrtcConn.onaddstream = gotRemoteStream;
    
    
        var req = new Object();
        req.type = "DESCRIBE";
        req.deviceId = deviceId.value;
        req.channelId = "0";
        req.playmode = "RECORD";
        req.startTime = startTime.value;
        req.endTime = "2021-10-1T24:00";
        console.log("start");
        websocketConn.send(JSON.stringify(req));
        m_playmode = "RECORD";
    }
    else
    {
        console.log("start record : connect ");
        connect();
    }
}
function playRecord() {
    var req = new Object();
    req.type = "PLAY";
    if(recordPauseFlag){
        req.startTime ="" ;
    }
    else{
        req.startTime = startTime.value;
    }
    
    req.endTime = "2021-10-1T24:00";
    req.scale = scaleInput.valueAsNumber;
    websocketConn.send(JSON.stringify(req));
    recordPauseFlag = false;
}

function pauseRecord() {
    var req = new Object();
    req.type = "PAUSE";
    console.log("pause");
    websocketConn.send(JSON.stringify(req));
    recordPauseFlag = true;
}

function tearDown() {
    var req = new Object();
    req.type = "TEARDOWN";
    console.log("pause");
    websocketConn.send(JSON.stringify(req));
    recordPauseFlag = false;
}

function handleMessage(evt) {
    console.log(evt.data);
    var res = JSON.parse(evt.data);
    if(res.code != 200)
    {
        webrtcConn.close();
        webrtcConn.close()
    }
    //接收服务器返回的offer
    if (res.type == "DESCRIBE") {
        var serverSdp = res.data;
        trace('remote offer \n' + serverSdp);
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
    if (res.type == "SETUP") {
        if (m_playmode == "RECORD") {
            playRecord();
        }
        if (m_playmode == "REALTIME") {
            playRealtime();
        }
    }

    if(res.type == "GET_RECORD_INDEX"){

        var first = timeIndexList.firstElementChild;
        while (first) {
            first.remove();
            first = timeIndexList.firstElementChild;
        }
        var nameObj = document.createElement("li");
        nameObj.innerText = "录像时间段";
        timeIndexList.appendChild(nameObj);
        for(var i=0;i<res.data.length;i++)
        {
            console.log(res.data.length);
            for(var j =0 ;j<res.data[i].time.length;j++){
                console.log(res.data[i].time.length);
                var liObj = document.createElement("li");
                var timeStr = res.data[i].year.toString() +"-"+ res.data[i].month.toString( ) +"-"+ res.data[i].day.toString()+ "  :  ";
                timeStr+=secondToTimepoint(res.data[i].time[j].startTime)+" - "+secondToTimepoint(res.data[i].time[j].endTime);
                liObj.innerText = timeStr;
                timeIndexList.appendChild(liObj);
            }
        }
        websocketConn.close();
        connFlag = false;
    }

    if(res.type == "TEARDOWN")
    {
        websocketConn.close();
        connFlag = false;
    }

}

function secondToTimepoint(time) {
    var hour = parseInt(time/3600);
    var min = parseInt(time%3600/60);
    var sec = parseInt(time%60);
    return hour.toString()+":"+min.toString()+":"+sec.toString();
}

function handleOpen() {
    if(currentclick == "play-realtime")
    {
        startRealtime();
    }
    if(currentclick == "play-record")
    {
        startRecord();
    }
    if(currentclick == "read-index")
    {
        readIndex();
    }

}

function connect() {
    console.log("connect");
    var ipPort = serverAddress.value;
    if (window["WebSocket"]) {
        var addr = "ws://" + ipPort;
        websocketConn = new WebSocket(addr);
        websocketConn.onopen = function (evt) {
            handleOpen();
            connFlag = true;
        }
        websocketConn.onerror = function (evt) {
            alert("WebSocket connect Error!");
            websocketConn.close();
            connFlag = false;
        }
        websocketConn.onclose = function (evt) {
            console.log('websocket close');
            connFlag = false;
            // websocketConn.close();
            //conn.close();
        }
        websocketConn.onmessage = handleMessage;
    }
    else {
        alert('Your browser does not support WebSocket')
    }
}

function startRealtime() {
    currentclick = "play-realtime";
    if (websocketConn&&websocketConn.readyState == WebSocket.OPEN) {
        console.log('Starting Call');
        var servers = null;
        webrtcConn = new RTCPeerConnection(servers);
        trace('Created peer connection');
        webrtcConn.onicecandidate = gotIceCandidate;
        webrtcConn.onaddstream = gotRemoteStream;
    
    
        var req = new Object();
        req.type = "DESCRIBE";
        req.deviceId = deviceId.value;
        req.playmode = "REALTIME";
        req.channelId = "0";
        console.log("start");
        websocketConn.send(JSON.stringify(req));
        m_playmode = "REALTIME";
    }
    else
    {
        connect();
    }
    

   
}

function playRealtime() {
    var req = new Object();
    req.type = "PLAY";
    websocketConn.send(JSON.stringify(req));
}

function pause() {
    var req = new Object();
    req.type = "TEARDOWN";
    console.log("pause");
    websocketConn.send(JSON.stringify(req));
}

function stop() {
    console.log("stop");
    websocketConn.close();
}


function onCreateSessionDescriptionError(error) {
    trace('Failed to create session description: ' + error.toString());
    stop();
}

function onCreateAnswerError(error) {
    trace('Failed to set createAnswer: ' + error.toString());
    stop();
}

function onSetLocalDescriptionError(error) {
    trace('Failed to set setLocalDescription: ' + error.toString());
    stop();
}

function onSetLocalDescriptionSuccess() {
    trace('localDescription success.');
}

function gotServerSdp(offer) {

    console.log('remote offer \n' + offer);
    var desc = new RTCSessionDescription();
    desc.sdp = offer;
    desc.type = 'offer';
    pc2.setRemoteDescription(desc);
    // Since the 'remote' side has no media stream we need
    // to pass in the right constraints in order for it to
    // accept the incoming offer of audio and video.
    pc2.createAnswer().then(
        sendClientSdp,
        onCreateSessionDescriptionError
    );
}

function sendClientSdp(desc) {
    // Provisional answer, set a=inactive & set sdp type to pranswer.
    /*desc.sdp = desc.sdp.replace(/a=recvonly/g, 'a=inactive');
    desc.type = 'pranswer';*/

    webrtcConn.setLocalDescription(desc).then(
        onSetLocalDescriptionSuccess,
        onSetLocalDescriptionError
    );
    trace('local sdp: ' + desc.sdp);

    var req = new Object();
    req.type = "ANNOUNCE";
    req.sdp = desc.sdp;
    websocketConn.send(JSON.stringify(req));
}


function gotRemoteStream(e) {
    webrtcStream.srcObject = e.stream;
    trace('Received remote stream');
}

function gotIceCandidate(event) {
    if (event.candidate) {
        console.log('local candidate: ' + event.candidate);

        var req = new Object();
        req.type = "SETUP";
        req.candidate = event.candidate;
        websocketConn.send(JSON.stringify(req));
    }
    else {
        // All ICE candidates have been sent
        console.log("got ice candidate is empty");
    }
}
