var express = require('express');
var app = express();

var fs = require('fs');
var xml = require('xml');
var cookieParser = require('cookie-parser');
var rs = require('random-strings');
var bodyParser = require('body-parser');
var Handlebars = require('handlebars');
var url = require('url');

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));

//databases
authenticatedTickets = {};
loginTickets = {};
authenticatedSessions = {};

//memory isn't going to work. need a DATABASE!!!

LOGIN_TICKET_EXPIRE_TIME = 1000*60*60; //LTs valid for 1hr
AUTH_SESSION_EXPIRE_TIME = 1000*60*60*24; //Auto-reauth without user/pass in 24h
TICKET_EXPIRE_TIME = 1000*60*60*24*7; //keep user authed for 1w

SERVER_NAME = 'https://dummycasserver.com';

//templates
pages = {};
page_names = ['login', 'logout', 'authSuccess'];
for(var p in page_names){
  pages[page_names[p]] = Handlebars.compile(fs.readFileSync(page_names[p]+'.hbs').toString());
}
function renderPage(name, data){ return pages[name](data); }


function generateLoginTicket(){
  var lt = 'LT-'+rs.alphaNumMixed(10);
  loginTickets[lt] = {timestamp: new Date().valueOf()}; //add allowed login ticket
  return lt;

}

function generateTicketGeneratingCookie(){
  return 'TGT-'+rs.alphaNumMixed(10);
}

function generateTicket(){
  return 'ST-'+rs.alphaNumMixed(10);
}

function appendTicketToService(service, ticket){
  var service_parsed = url.parse(service);
  service_parsed.query.push('ticket', ticket);
  return url.format(service_parsed);
}

function authenticateWithTicket(username, ticket){
  authenticatedTickets[ticket] = {
    username: username,
    timestamp: new Date().valueOf()
  };
}

function createValidSession(username){
  var tgc = generateTicketGeneratingCookie();
  authenticatedSessions[tgc] = {
    timestamp: new Date().valueOf(),
    username: username
  }
  return tgc;
}

function checkLoginTicket(loginTicket){
  var result =  (loginTicket && loginTickets[loginTicket]
      && loginTickets[loginTicket] > new Date().valueOf()-LOGIN_TICKET_EXPIRE_TIME);
  delete loginTickets[loginTicket]; //make sure that one can't be used again
  console.log('checkloginticket', loginTicket, loginTickets, result);
  return result;
}

function checkValidSession(session){
  return (!!session && authenticatedSessions[session]
    && authenticatedSessions[session].timestamp > new Date().valueOf() - AUTH_SESSION_EXPIRE_TIME);
}

function checkValidTicket(ticket){
  return (authenticatedTickets[ticket] > new Date().valueOf() - TICKET_EXPIRE_TIME);
}


//handles login requests
app.get('/login', function(req, res){

  /*
    renew: respond with login, even if already authed
    gateway: auth if already authed, otherwise, redirect to service without 'ticket'
    method: HTTP method for responses
  */


  var alreadyAuthed = checkValidSession(req.cookies['CASTGC']);

  console.log('already authed?', alreadyAuthed);

  // if(req.query.renew || !alreadyAuthed){
  //   //auth with form
  //   var loginTicket = generateLoginTicket();

  //   return res.send(renderPage('login', {
  //     loginTicket: loginTicket,
  //     service: req.query.service || ''
  //   }));
  // }

  // if(req.query.gateway && !alreadyAuthed){
  //   //redirect to service without ticket
  //   return res.send(renderPage('authSuccess', {
  //     service: req.query.service
  //   }));
  // }

  //othwerise they are good to go. make them a new ticket
  if(alreadyAuthed){
    var username = authenticatedSessions[session].username;
    var ticket = generateTicket();
    authenticateWithTicket(username, ticket);

    res.send(renderPage('authSuccess', {
      service: appendTicketToService(req.query.service, ticket)
    }));
  }else{
    var loginTicket = generateLoginTicket();
    res.send(renderPage('login', {
      loginTicket: loginTicket,
      service: req.query.service || ''
    }));
  }

});

//responds to login form
app.post('/login', function(req,res){

  var loginTicket = req.body.lt;
  var username = req.body.username;

  var service = req.query.service || req.body.service || '';

  var valid = checkLoginTicket(loginTicket); //spends loginTicket
  if(!valid || !username ){
    console.log('bad auth', valid, username);
    return res.redirect('/login?service='+service); //todo send timeout message
  }

  //otherwise auth was good
  var tgc = generateTicketGeneratingCookie(username); //used to auto-auth if not expired

  res.cookie('CASTGC', tgc); //set session cookie

  res.send(renderPage('authSuccess', {
    service: appendTicketToService(service, loginTicket)
  }));

});

app.post('/logout', function(req, res){
  delete authenticatedSessions[req.cookies['CASTGC']]; //destroy session
  req.cookie('CASTGC', ''); //delete cookie
  res.send(renderPage('logout', {
    service: req.query.service
  }));
});

// app.get('/validate', function(req, res){
//   res.send(
//       (authenticatedTickets[req.query.ticket] > new Date().valueOf() - TICKET_EXPIRE_TIME ? 'yes' : 'no')+"\n"
//     );
// });


app.get('/serviceValidate', function(req, res){
// <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
//  <cas:authenticationSuccess>
//   <cas:user>username</cas:user>
//   <cas:proxyGrantingTicket>PGTIOU-84678-8a9d...</cas:proxyGrantingTicket>
//  </cas:authenticationSuccess>
// </cas:serviceResponse>

// <cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
//  <cas:authenticationFailure code="INVALID_TICKET">
//     Ticket ST-1856339-aA5Yuvrxzpv8Tau1cYQ7 not recognized`
//   </cas:authenticationFailure>
// </cas:serviceResponse>

  if(checkValidTicket(req.query.ticket)){
    return res.send(xml({
      'cas:serviceResponse' : {
        '_attr': {'xmlns:cas': SERVER_NAME},
        'cas:authenticationSuccess': {
          'cas:user': authenticatedTickets[req.query.ticket].username,
          //cas:proxyGrantingTicket ??
        }
      }
    }));
  }else{
    return res.send(xml({
      'cas:serviceResponse': {
        '_attr': {'xmlns:cas': SERVER_NAME},
        'cas:authenticationFailure': [
          {'_attr': {'code': 'INVALID_TICKET'}},
          'Ticket '+req.query.ticket+' not recognized'
        ]
      }
    }));
  }
});

//TODO /proxyValidate, /proxy



app.listen(process.env.PORT || 5000);

//http://libcas.sourceforge.net/?id=casintro

//http://jasig.github.io/cas/development/protocol/CAS-Protocol-Specification.html#cas-protocol-30-specification

//http://jasig.github.io/cas/4.0.x/protocol/CAS-Protocol.html