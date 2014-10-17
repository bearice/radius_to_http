radius = require('radius')
dgram = require("dgram")
https = require("https")
qs = require("querystring")

server = dgram.createSocket("udp4")
secret = 'radius_proxy'

verify_remote = (user,pass,code,cb) ->
  console.info "Auth: user=#{user} pass=#{pass} code=#{code}"

  post_data = new Buffer qs.stringify
    'userName':user
    'passInfo':"#{pass}-#{code}"

  options =
    hostname: 'in.jimubox.com',
    path: '/Vpn/Validate',
    method: 'POST',
    headers:
      'Content-Type':'application/x-www-form-urlencoded',
      'Content-Length':post_data.length
      
  req = https.request options, (res) ->
    if res.statusCode !=200
      return cb(false)
    
    data = ""
    res.setEncoding('utf8')
    res.on 'data',  (chunk) ->
      data += chunk
    
    res.on 'end', ->
      try
        o = JSON.parse(data)
        console.info(o)
        cb(o.validate == "success")
      catch
        console.error _error
        cb(false)

  req.on 'error', (e) ->
    console.error "problem with request: #{e.message}"
    cb(false)

  req.write(post_data)
  req.end()

session_cache = {}

server.on "message",  (msg, rinfo) ->
  packet = radius.decode({packet: msg, secret: secret})
  console.log("Recv #{packet.code} for #{username}")

  if (packet.code != 'Access-Request')
    console.log('unknown packet type: ', packet.code)
    return

  #console.info(packet)
  username = packet.attributes['User-Name']
  password = packet.attributes['User-Password']
  sess_id  = packet.attributes['Acct-Session-Id']

  send_response = (code,attr) ->
    console.log("Send #{code} for user #{username}")
    response = radius.encode_response
      packet: packet
      code: code
      secret: secret
      attributes:  attr || []
    server.send response, 0, response.length, rinfo.port, rinfo.address, (err, bytes) ->
      if err
        console.log('Error sending response to ', rinfo)


  cached_passwd = session_cache[sess_id]
  if cached_passwd
    verify_remote username,cached_passwd,password,(ok)->
      code = "Access-Reject"
      code = "Access-Accept" if ok
      send_response code

  else
    session_cache[sess_id] = password
    #For fortigate firewalls, asks for token code
    send_response 'Access-Challenge',[
      ['Reply-Message', 'Please enter token:'],
      ['Vendor-Specific', 12356, [[15, new Buffer("001")]]]
    ]
    setTimeout (-> delete session_cache[sess_id]),5*60*1000

server.on "listening",  ->
  address = server.address()
  console.log("radius server listening " + address.address + ":" + address.port)
  
server.bind(1812)
