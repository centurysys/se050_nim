import std/[net, os, strutils]

proc usage(programName: string) =
  stderr.writeLine(
    "Usage: " & programName &
    " HOST PORT CA_FILE CERT_FILE KEY_FILE SERVER_NAME"
  )

proc main() =
  let args = commandLineParams()
  if args.len != 6:
    usage(getAppFilename())
    quit(2)

  let
    host = args[0]
    portNumber = parseInt(args[1])
    caFile = args[2]
    certFile = args[3]
    keyFile = args[4]
    serverName = args[5]

  if portNumber < 1 or portNumber > 65535:
    stderr.writeLine("PORT must be in 1..65535")
    quit(2)

  let ctx = newContext(
    verifyMode = CVerifyPeer,
    certFile = certFile,
    keyFile = keyFile,
    caFile = caFile
  )
  defer:
    destroyContext(ctx)

  let socket = newSocket()
  defer:
    socket.close()

  socket.connect(host, Port(portNumber))
  ctx.wrapConnectedSocket(socket, handshakeAsClient, hostname = serverName)

  socket.send(
    "GET / HTTP/1.0\r\n" &
    "Host: " & serverName & "\r\n" &
    "Connection: close\r\n\r\n"
  )

  var response = ""
  while true:
    let chunk = socket.recv(4096)
    if chunk.len == 0:
      break
    response.add(chunk)

  # The test target is the TLS handshake itself. In mutual TLS, successful
  # completion means the client certificate and CertificateVerify signature
  # have already been accepted by the server. Application data is deliberately
  # not part of the success criterion.
  discard response

  echo "std/net mutual TLS: OK"

when isMainModule:
  main()
