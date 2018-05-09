{-# LANGUAGE RebindableSyntax, TemplateHaskell #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE RecursiveDo #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Main where

import Prelude hiding
  ( (>>=)
  , return
  , fail
  , (>>)
#if ! MIN_VERSION_base(4,6,0)
  , catch
#endif
  )
import Network.Transport
import Network.Transport.TCP.TLS ( createTransport
                             , createTransportExposeInternals
                             , TransportInternals(..)
                             , TCPParameters(..)
                             , defaultTCPParameters
                             , LightweightConnectionId
                             , TCPAddrInfo(..)
                             , TCPAddr(..)
                             , defaultTCPAddr
                             , socketToEndPoint

                             , TLSConfig
                             , mkTLSConfig
                             , mkTLSClientParams
                             , mkTLSServerParams
                             , defaultSupported
                             , mkShared
                             , loadCredentials
                             , handshake
                             , recvTLS
                             , sendTLS'
                             , addLoggingHooks
                             )
import Control.Concurrent (threadDelay, killThread, myThreadId)
import Control.Concurrent.MVar ( MVar
                               , newEmptyMVar
                               , putMVar
                               , takeMVar
                               , readMVar
                               , isEmptyMVar
                               , newMVar
                               , modifyMVar
                               , modifyMVar_
                               , swapMVar
                               )
import Control.Monad (replicateM, guard, forM_, replicateM_, when)
import Control.Applicative ((<$>))
import Control.Exception (throwIO, try, SomeException, catch, IOException)
import Network.Transport.Internal ( prependLength
                                  , tryIO
                                  , void
                                  )
import Network.Transport.TCP.Internal
  ( ControlHeader(..)
  , encodeControlHeader
  , decodeControlHeader
  , ConnectionRequestResponse(..)
  , encodeConnectionRequestResponse
  , decodeConnectionRequestResponse
  , encodeWord32
  , recvWord32
  , forkServer
  , recvWithLength
  , encodeEndPointAddress
  , decodeEndPointAddress
  )

import qualified Network.TLS as TLS

#ifdef USE_MOCK_NETWORK
import qualified Network.Transport.TCP.Mock.Socket as N
#else
import qualified Network.Socket as N
#endif
  ( ServiceName
  , Socket
  , socketPort
  , AddrInfo
  , shutdown
  , ShutdownCmd(ShutdownSend)
  , SockAddr(..)
  , SocketType(Stream)
  , AddrInfo(..)
  , getAddrInfo
  , defaultHints
  , defaultProtocol
  , socket
  , connect
  , close
  )

#ifdef USE_MOCK_NETWORK
import Network.Transport.TCP.Mock.Socket.ByteString (sendMany)
#else
import Network.Socket.ByteString (sendMany)
#endif

import Control.Monad.IO.Class (MonadIO, liftIO)

import qualified Data.ByteString as BS (ByteString, append, length, concat)
import Data.String (fromString)
import GHC.IO.Exception (ioe_errno)
import Foreign.C.Error (Errno(..), eADDRNOTAVAIL)
import System.Timeout (timeout)
import Network.Transport.Tests (testTransport)
import Network.Transport.Tests.Auxiliary (forkTry, runTests)
import Network.Transport.Tests.Traced

import System.IO

instance Traceable ControlHeader where
  trace = traceShow

instance Traceable ConnectionRequestResponse where
  trace = traceShow

instance Traceable N.Socket where
  trace = traceShow

instance Traceable N.AddrInfo where
  trace = traceShow

instance Traceable TransportInternals where
  trace = const Nothing

instance Traceable TLS.Context where
  trace _ = trace ("TLS.Context" :: String)

instance Traceable TLS.ServerParams where
  trace _ = trace ("TLS.ServerParams" :: String)

instance Traceable TLS.ClientParams where
  trace _ = trace ("TLS.ClientParams" :: String)

instance Traceable TLSConfig where
  trace _ = trace ("TLSConfig" :: String)

instance Traceable TLS.Credentials where
  trace _ = trace ("TLS.Credentials" :: String)

instance Traceable TCPParameters where
  trace _ = trace ("TCPParameters" :: String)

-- tlog msg = return ()
tlog msg = liftIO $ do
  tid <- myThreadId
  putStrLn $ show tid ++ ": "  ++ msg
  hFlush stdout
  hFlush stderr

testTCPParametersTLS :: IO TCPParameters
testTCPParametersTLS = do
  Right testTLSConfig <-
    mkTLSConfig defaultSupported ("tests/server_cert.pem", "tests/server_key.pem") Nothing Nothing
  pure $ defaultTCPParameters testTLSConfig

testTLSClientParams :: EndPointAddress -> IO TLS.ClientParams
testTLSClientParams epAddr = do
  Right tlsClientParams <-
    mkTLSClientParams defaultSupported (mkShared Nothing Nothing) epAddr
  pure tlsClientParams

testTLSServerParams :: IO TLS.ServerParams
testTLSServerParams = do
  Right serverCreds <- loadCredentials "tests/server_cert.pem" "tests/server_key.pem"
  mkTLSServerParams defaultSupported (mkShared Nothing (Just serverCreds)) Nothing

-- | Sets up a client TLS context and then initiates a handshake on the socket
tlsHandshakeClient :: TLS.ClientParams -> N.Socket -> EndPointAddress -> IO TLS.Context
tlsHandshakeClient clientParams sock clientAddr = do
  clientTLSContext <- TLS.contextNew sock clientParams
  let ourAddrPref = "(" ++ show clientAddr ++ ") "
  let tlsHandshake = do
        tlog $ ourAddrPref ++ "Starting client TLS handshake..."
        -- TLS.contextModifyHooks clientTLSContext (addLoggingHooks "T-CLIENT")
        TLS.handshake clientTLSContext
        tlog $ ourAddrPref ++ "Finished client TLS handshake."
  () <- tlsHandshake
  pure clientTLSContext

-- | Sets up a server TLS context and then initiates a handshake on the socket
tlsHandshakeServer :: TLS.ServerParams -> N.Socket -> EndPointAddress -> IO TLS.Context
tlsHandshakeServer serverParams sock serverAddr = do
  serverTLSContext <- TLS.contextNew sock serverParams
  let ourAddrPref = "(" ++ "client" ++ ") "
  let tlsHandshake = do
        tlog $ ourAddrPref ++ "Starting server TLS handshake..."
        -- TLS.contextModifyHooks serverTLSContext (addLoggingHooks "T-SERVER")
        TLS.handshake serverTLSContext
        tlog $ ourAddrPref ++ "Finished server TLS handshake."
  () <- tlsHandshake
  pure serverTLSContext

-- Test that the server gets a ConnectionClosed message when the client closes
-- the socket without sending an explicit control message to the server first
testEarlyDisconnect :: IO ()
testEarlyDisconnect = do
    clientAddr <- newEmptyMVar
    serverAddr <- newEmptyMVar
    serverDone <- newEmptyMVar

    tlog "testEarlyDisconnect"
    forkTry $ server serverAddr clientAddr serverDone
    forkTry $ client serverAddr clientAddr

    takeMVar serverDone
  where
    server :: MVar EndPointAddress -> MVar EndPointAddress -> MVar () -> IO ()
    server serverAddr clientAddr serverDone = do
      tlog "Server"
      Right transport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
      Right endpoint  <- newEndPoint transport
      putMVar serverAddr (address endpoint)
      theirAddr <- readMVar clientAddr

      -- TEST 1: they connect to us, then drop the connection
      do
        tlog "Server: Trying to recv ConnectionOpened"
        ConnectionOpened _ _ addr <- receive endpoint
        True <- return $ addr == theirAddr

        tlog "Server: Trying to recv EventConnectionLost"
        ErrorEvent (TransportError (EventConnectionLost addr') _) <- receive endpoint
        True <- return $ addr' == theirAddr

        return ()

      -- TEST 2: after they dropped their connection to us, we now try to
      -- establish a connection to them. This should re-establish the broken
      -- TCP connection.
      tlog "Server: Trying to connect to client"
      Right conn <- connect endpoint theirAddr ReliableOrdered defaultConnectHints

      -- TEST 3: To test the connection, we do a simple ping test; as before,
      -- however, the remote client won't close the connection nicely but just
      -- closes the socket
      do
        tlog "Server: sending 'ping'"
        Right () <- send conn ["ping"]

        tlog "Server: Trying to recv ConnectionOpened again..."
        ConnectionOpened cid _ addr <- receive endpoint
        True <- return $ addr == theirAddr

        tlog "Server: Trying to recv pong msg"
        Received cid' ["pong"] <- receive endpoint
        True <- return $ cid == cid'

        ErrorEvent (TransportError (EventConnectionLost addr') _) <- receive endpoint
        True <- return $ addr' == theirAddr

        return ()

      -- TEST 4: A subsequent send on an already-open connection will now break
      Left (TransportError SendFailed _) <- send conn ["ping2"]

      -- *Pfew*
      putMVar serverDone ()

    client :: MVar EndPointAddress -> MVar EndPointAddress -> IO ()
    client serverAddr clientAddr = do
      tlog "Client"

      -- Listen for incoming messages
      (clientPort, _) <- forkServer "127.0.0.1" "0" 5 True throwIO throwIO $ \socketFree (sock, _) -> do

        -- Initial setup
        tlog "Client: Trying to recv 0"
        0 <- recvWord32 sock
        tlog "Client: Trying to recvWithLength"
        _ <- recvWithLength maxBound sock
        tlog "Client: Sending ConnectionRequestAccepted"
        sendMany sock [encodeWord32 (encodeConnectionRequestResponse ConnectionRequestAccepted)]

        -- Initiate the server TLS handshake on connection receipt
        port <- show <$> N.socketPort sock
        let ourAddress = encodeEndPointAddress "127.0.0.1" port 1
        tlsCtxt <- testTLSServerParams >>= \serverParams ->
          tlsHandshakeServer serverParams sock ourAddress

        tlog "Client: Server opens a logical connection, recvs CreatedNewConnection"
        Just CreatedNewConnection <- decodeControlHeader <$> recvWord32 sock
        1024 <- recvWord32 sock :: IO LightweightConnectionId

        -- Server sends a message
        tlog "Client: Server sends me a message, trying to recv it"
        1024 <- recvWord32 sock
        tlog "Client: Server sends me a message, trying to recv it 2"
        "ping" <- recvTLS (tlsCtxt, sock) maxBound

        -- Reply
        tlog "Client: Sending CreatedNewConnection to server"
        sendMany sock [
            encodeWord32 (encodeControlHeader CreatedNewConnection)
          , encodeWord32 10002
          ]

        sendMany sock [encodeWord32 10002]
        sendTLS' (tlsCtxt, sock) "pong"

        -- Close the socket
        N.close sock

      let ourAddress = encodeEndPointAddress "127.0.0.1" clientPort 0
      putMVar clientAddr ourAddress

      tlog "Client: Connect to the server"
      serverAddress <- readMVar serverAddr
      Right (_, sock, ConnectionRequestAccepted) <-
        socketToEndPoint (Just ourAddress) serverAddress True False False Nothing Nothing

      -- Establish a client TLS context since this endpoint is the one
      -- intiating the connection
      tlsClientParams <- testTLSClientParams serverAddress
      ctxt <- tlsHandshakeClient tlsClientParams sock ourAddress

      tlog "Client: Open a new connection"
      sendMany sock [
          encodeWord32 (encodeControlHeader CreatedNewConnection)
        , encodeWord32 10003
        ]

      -- Close the socket without closing the connection explicitly
      -- The server should receive an error event
      N.close sock

-- | Test the behaviour of a premature CloseSocket request
testEarlyCloseSocket :: IO ()
testEarlyCloseSocket = do
    clientAddr <- newEmptyMVar
    serverAddr <- newEmptyMVar
    serverDone <- newEmptyMVar

    tlog "testEarlyDisconnect"
    forkTry $ server serverAddr clientAddr serverDone
    forkTry $ client serverAddr clientAddr

    takeMVar serverDone
  where
    server :: MVar EndPointAddress -> MVar EndPointAddress -> MVar () -> IO ()
    server serverAddr clientAddr serverDone = do
      tlog "Server"
      Right transport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
      Right endpoint  <- newEndPoint transport
      putMVar serverAddr (address endpoint)
      theirAddr <- readMVar clientAddr

      -- TEST 1: they connect to us, then send a CloseSocket. Since we don't
      -- have any outgoing connections, this means we will agree to close the
      -- socket
      do
        ConnectionOpened cid _ addr <- receive endpoint
        True <- return $ addr == theirAddr

        ConnectionClosed cid' <- receive endpoint
        True <- return $ cid' == cid

        return ()

      -- TEST 2: after they dropped their connection to us, we now try to
      -- establish a connection to them. This should re-establish the broken
      -- TCP connection.
      tlog "Trying to connect to client"
      Right conn <- connect endpoint theirAddr ReliableOrdered defaultConnectHints

      -- TEST 3: To test the connection, we do a simple ping test; as before,
      -- however, the remote client won't close the connection nicely but just
      -- sends a CloseSocket -- except that now we *do* have outgoing
      -- connections, so we won't agree and hence will receive an error when
      -- the socket gets closed
      do
        tlog "Server: Sending 'ping' message"
        Right () <- send conn ["ping"]

        ConnectionOpened cid _ addr <- receive endpoint
        True <- return $ addr == theirAddr

        Received cid' ["pong"] <- receive endpoint
        True <- return $ cid' == cid

        ConnectionClosed cid'' <- receive endpoint
        True <- return $ cid'' == cid

        ErrorEvent (TransportError (EventConnectionLost addr') _) <- receive endpoint
        True <- return $ addr' == theirAddr

        return ()

      -- TEST 4: A subsequent send on an already-open connection will now break
      Left (TransportError SendFailed _) <- send conn ["ping2"]

      -- *Pfew*
      putMVar serverDone ()

    client :: MVar EndPointAddress -> MVar EndPointAddress -> IO ()
    client serverAddr clientAddr = do
      tlog "Client"

      -- Listen for incoming messages
      (clientPort, _) <- forkServer "127.0.0.1" "0" 5 True throwIO throwIO $ \socketFree (sock, _) -> do
        -- Initial setup
        0 <- recvWord32 sock
        _ <- recvWithLength maxBound sock
        sendMany sock [encodeWord32 (encodeConnectionRequestResponse ConnectionRequestAccepted)]

        -- Initiate the server TLS handshake on connection receipt
        port <- show <$> N.socketPort sock
        let ourAddress = encodeEndPointAddress "127.0.0.1" port 1
        tlsServerParams <- testTLSServerParams
        tlsCtxt <- tlsHandshakeServer tlsServerParams  sock ourAddress

        -- Server opens a logical connection
        Just CreatedNewConnection <- decodeControlHeader <$> recvWord32 sock
        1024 <- recvWord32 sock :: IO LightweightConnectionId

        -- Server sends a message
        tlog "Client: Waiting for 'ping' msg"
        1024 <- recvWord32 sock
        "ping" <- recvTLS (tlsCtxt, sock) maxBound

        -- Reply
        tlog "Client: Sending 'pong' msg"
        sendMany sock [
            encodeWord32 (encodeControlHeader CreatedNewConnection)
          , encodeWord32 10002
          ]

        sendMany sock [encodeWord32 10002]
        sendTLS' (tlsCtxt, sock) "pong"

        -- Send a CloseSocket even though there are still connections *in both
        -- directions*
        sendMany sock [
            encodeWord32 (encodeControlHeader CloseSocket)
          , encodeWord32 1024
          ]
        N.close sock

      let ourAddress = encodeEndPointAddress "127.0.0.1" clientPort 0
      putMVar clientAddr ourAddress

      -- Connect to the server
      serverAddress <- readMVar serverAddr
      Right (_, sock, ConnectionRequestAccepted) <-
        socketToEndPoint (Just ourAddress) serverAddress True False False Nothing Nothing

      -- Establish a client TLS context since this endpoint is the one
      -- intiating the connection
      tlsClientParams <- testTLSClientParams serverAddress
      tlsCtx <- tlsHandshakeClient tlsClientParams sock ourAddress

      -- Open a new connection
      sendMany sock [
          encodeWord32 (encodeControlHeader CreatedNewConnection)
        , encodeWord32 10003
        ]

      -- Send a CloseSocket without sending a closeconnecton
      -- The server should still receive a ConnectionClosed message
      sendMany sock [
          encodeWord32 (encodeControlHeader CloseSocket)
        , encodeWord32 0
        ]
      N.close sock

-- | Test the creation of a transport with an invalid address
testInvalidAddress :: IO ()
testInvalidAddress = do
  Left _ <- createTransport (defaultTCPAddr "invalidHostName" "0") =<< testTCPParametersTLS
  return ()

-- | Test connecting to invalid or non-existing endpoints
testInvalidConnect :: IO ()
testInvalidConnect = do
  Right transport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
  Right endpoint  <- newEndPoint transport

  -- Syntax error in the endpoint address
  Left (TransportError ConnectFailed _) <-
    connect endpoint (EndPointAddress "InvalidAddress") ReliableOrdered defaultConnectHints

  -- Syntax connect, but invalid hostname (TCP address lookup failure)
  Left (TransportError ConnectNotFound _) <-
    connect endpoint (encodeEndPointAddress "invalidHost" "port" 0) ReliableOrdered defaultConnectHints

  -- TCP address correct, but nobody home at that address
  Left (TransportError ConnectNotFound _) <-
    connect endpoint (encodeEndPointAddress "127.0.0.1" "9000" 0) ReliableOrdered defaultConnectHints

  -- Valid TCP address but invalid endpoint number
  Left (TransportError ConnectNotFound _) <-
    connect endpoint (encodeEndPointAddress "127.0.0.1" "0" 1) ReliableOrdered defaultConnectHints

  return ()

-- | Test that an endpoint can ignore CloseSocket requests (in "reality" this
-- would happen when the endpoint sends a new connection request before
-- receiving an (already underway) CloseSocket request)
testIgnoreCloseSocket :: IO ()
testIgnoreCloseSocket = do
  serverAddr <- newEmptyMVar
  clientAddr <- newEmptyMVar
  clientDone <- newEmptyMVar
  serverDone <- newEmptyMVar
  connectionEstablished <- newEmptyMVar
  Right transport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS

  -- Server
  forkTry $ do
    tlog "Server"
    Right endpoint <- newEndPoint transport
    putMVar serverAddr (address endpoint)

    let ourAddress = address endpoint
    theirAddress <- readMVar clientAddr

    -- Wait for the client to set up the TCP connection to us
    takeMVar connectionEstablished

    -- Connect then disconnect to the client
    Right conn <- connect endpoint theirAddress ReliableOrdered defaultConnectHints
    close conn

    -- At this point the server will have sent a CloseSocket request to the
    -- client, which however ignores it, instead it requests and closes
    -- another connection
    tlog "Waiting for ConnectionOpened"
    ConnectionOpened _ _ _ <- receive endpoint
    tlog "Waiting for ConnectionClosed"
    ConnectionClosed _ <- receive endpoint

    putMVar serverDone ()

  -- Client
  forkTry $ do
    tlog "Client"
    Right endpoint <- newEndPoint transport
    putMVar clientAddr (address endpoint)

    let ourAddress = address endpoint
    theirAddress <- readMVar serverAddr

    -- Connect to the server
    Right (_, sock, ConnectionRequestAccepted) <-
      socketToEndPoint (Just ourAddress) theirAddress True False False Nothing Nothing
    putMVar connectionEstablished ()

    -- Initiate a TLS handshake with the server
    tlsClientParams <- testTLSClientParams theirAddress
    tlsCtx <- tlsHandshakeClient tlsClientParams sock ourAddress

    -- Server connects to us, and then closes the connection
    Just CreatedNewConnection <- decodeControlHeader <$> recvWord32 sock
    1024 <- recvWord32 sock :: IO LightweightConnectionId

    Just CloseConnection <- decodeControlHeader <$> recvWord32 sock
    1024 <- recvWord32 sock :: IO LightweightConnectionId

    -- Server will now send a CloseSocket request as its refcount reached 0
    tlog "Waiting for CloseSocket request"
    Just CloseSocket <- decodeControlHeader <$> recvWord32 sock
    _ <- recvWord32 sock :: IO LightweightConnectionId

    -- But we ignore it and request another connection in the other direction
    tlog "Ignoring it, requesting another connection"
    sendMany sock [
        encodeWord32 (encodeControlHeader CreatedNewConnection)
      , encodeWord32 1024
      ]

    -- Close it again
    tlog "Closing connection"
    sendMany sock [
        encodeWord32 (encodeControlHeader CloseConnection)
      , encodeWord32 1024
      ]

    -- And close the connection completely
    tlog "Closing socket"
    sendMany sock [
        encodeWord32 (encodeControlHeader CloseSocket)
      , encodeWord32 1024
      ]
    N.close sock

    putMVar clientDone ()

  takeMVar clientDone
  takeMVar serverDone

-- | Like 'testIgnoreSocket', but now the server requests a connection after the
-- client closed their connection. In the meantime, the server will have sent a
-- CloseSocket request to the client, and must block until the client responds.
testBlockAfterCloseSocket :: IO ()
testBlockAfterCloseSocket = do
  serverAddr <- newEmptyMVar
  clientAddr <- newEmptyMVar
  clientDone <- newEmptyMVar
  serverDone <- newEmptyMVar
  connectionEstablished <- newEmptyMVar
  Right transport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS

  -- Server
  forkTry $ do
    tlog "Server"
    Right endpoint <- newEndPoint transport
    putMVar serverAddr (address endpoint)

    let ourAddress = address endpoint
    theirAddress <- readMVar clientAddr

    -- Wait for the client to set up the TCP connection to us
    takeMVar connectionEstablished

    -- Connect then disconnect to the client
    Right conn <- connect endpoint theirAddress ReliableOrdered defaultConnectHints
    close conn

    -- At this point the server will have sent a CloseSocket request to the
    -- client, and must block until the client responds
    Right conn <- connect endpoint theirAddress ReliableOrdered defaultConnectHints

    putMVar serverDone ()

  -- Client
  forkTry $ do
    tlog "Client"
    Right endpoint <- newEndPoint transport
    putMVar clientAddr (address endpoint)

    let ourAddress = address endpoint
    theirAddress <- readMVar serverAddr

    -- Connect to the server
    Right (_, sock, ConnectionRequestAccepted) <- socketToEndPoint (Just ourAddress) theirAddress True False False Nothing Nothing
    putMVar connectionEstablished ()

    -- Initiate a TLS handshake with the client
    tlsClientParams <- testTLSClientParams theirAddress
    tlsCtx <- tlsHandshakeClient tlsClientParams sock ourAddress

    -- Server connects to us, and then closes the connection
    Just CreatedNewConnection <- decodeControlHeader <$> recvWord32 sock
    1024 <- recvWord32 sock :: IO LightweightConnectionId

    Just CloseConnection <- decodeControlHeader <$> recvWord32 sock
    1024 <- recvWord32 sock :: IO LightweightConnectionId

    -- Server will now send a CloseSocket request as its refcount reached 0
    tlog "Waiting for CloseSocket request"
    Just CloseSocket <- decodeControlHeader <$> recvWord32 sock
    _ <- recvWord32 sock :: IO LightweightConnectionId

    unblocked <- newMVar False

    -- We should not hear from the server until we unblock him by
    -- responding to the CloseSocket request (in this case, we
    -- respond by sending a ConnectionRequest)
    forkTry $ do
      recvWord32 sock
      readMVar unblocked >>= guard
      putMVar clientDone ()

    threadDelay 1000000

    tlog "Client ignores close socket and sends connection request"
    tlog "This should unblock the server"
    modifyMVar_ unblocked $ \_ -> return True
    sendMany sock [
        encodeWord32 (encodeControlHeader CreatedNewConnection)
      , encodeWord32 1024
      ]

  takeMVar clientDone
  takeMVar serverDone

-- | Test what happens when a remote endpoint sends a connection request to our
-- transport for an endpoint it already has a connection to
testUnnecessaryConnect :: Int -> IO ()
testUnnecessaryConnect numThreads = do
  clientDone <- newEmptyMVar
  serverAddr <- newEmptyMVar

  forkTry $ do
    Right transport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
    Right endpoint <- newEndPoint transport
    -- Since we're lying about the server's address, we have to manually
    -- construct the proper address. If we used its actual address, the clients
    -- would try to resolve "128.0.0.1" and then would fail due to invalid
    -- address.
    Just (_, port, epid) <- return $ decodeEndPointAddress (address endpoint)
    putMVar serverAddr $ encodeEndPointAddress "127.0.0.1" port epid

  forkTry $ do
    -- We pick an address < 128.0.0.1 so that this is not rejected purely because of the "crossed" check
    let ourAddress = encodeEndPointAddress "127.0.0.1" "1234" 0

    -- We should only get a single 'Accepted' reply
    gotAccepted <- newEmptyMVar
    dones <- replicateM numThreads $ do
      done <- newEmptyMVar
      forkTry $ do
        -- It is possible that the remote endpoint just rejects the request by closing the socket
        -- immediately (depending on far the remote endpoint got with the initialization)
        response <- readMVar serverAddr >>= \addr -> socketToEndPoint (Just ourAddress) addr True False False Nothing Nothing
        case response of
          Right (_, _, ConnectionRequestAccepted) ->
            -- We don't close this socket because we want to keep this connection open
            putMVar gotAccepted ()
          -- We might get either Invalid or Crossed (the transport does not
          -- maintain enough history to be able to tell)
          Right (_, sock, ConnectionRequestInvalid) ->
            N.close sock
          Right (_, sock, ConnectionRequestCrossed) ->
            N.close sock
          Left _ ->
            return ()
        putMVar done ()
      return done

    mapM_ readMVar (gotAccepted : dones)
    putMVar clientDone ()

  takeMVar clientDone

-- | Test that we can create "many" transport instances
testMany :: IO ()
testMany = do
  Right masterTransport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
  Right masterEndPoint  <- newEndPoint masterTransport

  replicateM_ 10 $ do
    mTransport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
    case mTransport of
      Left ex -> do
        putStrLn $ "IOException: " ++ show ex ++ "; errno = " ++ show (ioe_errno ex)
        case (ioe_errno ex) of
          Just no | Errno no == eADDRNOTAVAIL -> putStrLn "(ADDRNOTAVAIL)"
          _ -> return ()
        throwIO ex
      Right transport ->
        replicateM_ 2 $ do
          Right endpoint <- newEndPoint transport
          Right _        <- connect endpoint (address masterEndPoint) ReliableOrdered defaultConnectHints
          return ()

-- | Test what happens when the transport breaks completely
testBreakTransport :: IO ()
testBreakTransport = do
  Right (transport, internals) <- createTransportExposeInternals (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
  Right endpoint <- newEndPoint transport

  let Just tid = transportThread internals
  killThread tid -- Uh oh

  ErrorEvent (TransportError EventTransportFailed _) <- receive endpoint

  return ()

-- Used in testReconnect to block until a socket is closed. newtype is needed
-- for the Traceable instance.
newtype WaitSocketFree = WaitSocketFree (IO ())

instance Traceable WaitSocketFree where
  trace = const Nothing

-- | Test that a second call to 'connect' might succeed even if the first
-- failed. This is a TCP specific test rather than an endpoint specific test
-- because we must manually create the endpoint address to match an endpoint we
-- have yet to set up.
-- Then test that we get a connection lost message after the remote endpoint
-- suddenly closes the socket, and that a subsequent 'connect' allows us to
-- re-establish a connection to the same endpoint
testReconnect :: IO ()
testReconnect = do
  serverDone      <- newEmptyMVar
  endpointCreated <- newEmptyMVar
  -- The server will put the 'socketFree' IO in here, so that the client can
  -- block until the server has closed the socket.
  socketClosed    <- newEmptyMVar

  counter <- newMVar (0 :: Int)

  -- Server
  (serverPort, _) <- forkServer "127.0.0.1" "0" 5 True throwIO throwIO $ \socketFree (sock, _) -> do
    -- Accept the connection
    Right 0  <- tryIO $ recvWord32 sock
    Right _  <- tryIO $ recvWithLength maxBound sock

    -- The first time we close the socket before accepting the logical connection
    count <- modifyMVar counter $ \i -> return (i + 1, i)

    -- Wait 100ms after the socket closes, to (hopefully) ensure that the client
    -- knows the connection is closed, and sending on that socket will therefore
    -- fail.
    putMVar socketClosed (WaitSocketFree (socketFree >> threadDelay 100000))

    when (count > 0) $ do
      -- The second, third, and fourth connections are accepted according to the
      -- protocol.
      -- On the second request, the socket then closes.
      Right () <- tryIO $ sendMany sock [
          encodeWord32 (encodeConnectionRequestResponse ConnectionRequestAccepted)
        ]

      -- Initiate the server TLS handshake on connection receipt
      port <- show <$> N.socketPort sock
      let ourAddress = encodeEndPointAddress "127.0.0.1" port 1
      tlsServerParams <- testTLSServerParams
      tlsCtxt <- tlsHandshakeServer tlsServerParams sock ourAddress

      -- Client requests a logical connection
      when (count > 1) $ do
        -- On the third and fourth requests, a new logical connection is
        -- accepted.
        -- On the third request the socket then closes.
        Right (Just CreatedNewConnection) <- tryIO $ decodeControlHeader <$> recvWord32 sock
        connId <- recvWord32 sock :: IO LightweightConnectionId

        when (count > 2) $ do
          -- On the fourth request, a message is received and then the socket
          -- is closed.
          Right connId' <- tryIO $ (recvWord32 sock :: IO LightweightConnectionId)
          True <- return $ connId == connId'
          Right "ping" <- tryIO $ recvTLS (tlsCtxt, sock) maxBound
          putMVar serverDone ()

    return ()

  putMVar endpointCreated ()

  -- Client
  forkTry $ do
    Right transport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
    Right endpoint  <- newEndPoint transport
    let theirAddr = encodeEndPointAddress "127.0.0.1" serverPort 0

    takeMVar endpointCreated

    -- First attempt: fails because the server closes the socket without
    -- doing the handshake.
    resultConnect <- connect endpoint theirAddr ReliableOrdered defaultConnectHints
    case resultConnect of
      Left (TransportError ConnectFailed _) -> return ()
      Left err -> throwIO err
      Right _ -> throwIO $ userError "testConnect: unexpected connect success"
    WaitSocketFree wait <- takeMVar socketClosed
    wait

    -- Second attempt: server accepts the connection but then closes the socket.
    -- We expect a failed connection if the socket is closed *before*
    -- CreatedNewConnection is sent, or a successful connection such that a
    -- subsequent send will fail in case CreatedNewConnection was sent before
    -- the close.
    resultConnect <- connect endpoint theirAddr ReliableOrdered defaultConnectHints
    -- We must be sure that the socket has closed before trying to send.
    WaitSocketFree wait <- takeMVar socketClosed
    wait
    case resultConnect of
      Left (TransportError ConnectFailed _) -> return ()
      Left err -> throwIO err
      Right c -> do
        ev <- send c ["ping"]
        case ev of
          Left _ -> return ()
          Right _ -> throwIO $ userError "testConnect: unexpected send success"

    -- In any case, since a heavyweight connection was made, we'll get a
    -- connection lost event.
    ErrorEvent (TransportError (EventConnectionLost _) _) <- receive endpoint

    -- Third attempt: server accepts the heavyweight and the lightweight
    -- connection (CreatedNewConnection) but then closes the socket.
    -- The connection must succeed, but sending after the socket is closed
    -- must fail.
    resultConnect <- connect endpoint theirAddr ReliableOrdered defaultConnectHints
    -- Wait until close before trying to send.
    WaitSocketFree wait <- takeMVar socketClosed
    wait
    case resultConnect of
      Left err -> throwIO err
      Right c -> do
        ev <- send c ["ping"]
        case ev of
          Left (TransportError SendFailed _) -> return ()
          Left err -> throwIO err
          Right _ -> throwIO $ userError "testConnect: unexpected send success"

    ErrorEvent (TransportError (EventConnectionLost _) _) <- receive endpoint

    -- But a subsequent call to connect should reestablish the connection
    Right conn2 <- connect endpoint theirAddr ReliableOrdered defaultConnectHints

    -- Send should now succeed
    Right () <- send conn2 ["ping"]

    WaitSocketFree wait <- takeMVar socketClosed
    wait
    return ()

  takeMVar serverDone

-- Test what happens if we close the socket one way only. This means that the
-- 'recv' in 'handleIncomingMessages' will not fail, but a 'send' or 'connect'
-- *will* fail. We are testing that error handling everywhere does the right
-- thing.
testUnidirectionalError :: IO ()
testUnidirectionalError = do
  clientDone <- newEmptyMVar
  serverGotPing <- newEmptyMVar

  -- Server
  (serverPort, _) <- forkServer "127.0.0.1" "0" 5 True throwIO throwIO $ \socketFree (sock, _) -> do
    -- We accept connections, but when an exception occurs we don't do
    -- anything (in particular, we don't close the socket). This is important
    -- because when we shutdown one direction of the socket a recv here will
    -- fail, but we don't want to close that socket at that point (which
    -- would shutdown the socket in the other direction)
    void . (try :: IO () -> IO (Either SomeException ())) $ do
      0 <- recvWord32 sock
      _ <- recvWithLength maxBound sock
      () <- sendMany sock [encodeWord32 (encodeConnectionRequestResponse ConnectionRequestAccepted)]

      -- Initiate the server TLS handshake on connection receipt
      port <- show <$> N.socketPort sock
      let ourAddress = encodeEndPointAddress "127.0.0.1" port 1
      tlsServerParams <- testTLSServerParams
      tlsCtxt <- tlsHandshakeServer tlsServerParams sock ourAddress

      Just CreatedNewConnection <- decodeControlHeader <$> recvWord32 sock
      connId <- recvWord32 sock :: IO LightweightConnectionId

      connId' <- recvWord32 sock :: IO LightweightConnectionId
      True <- return $ connId == connId'
      "ping" <- recvTLS (tlsCtxt, sock) maxBound
      putMVar serverGotPing ()

    -- Must read the clientDone MVar so that we don't close the socket
    -- (forkServer will close it once this action ends).
    readMVar clientDone

  -- Client
  forkTry $ do
    Right (transport, internals) <- createTransportExposeInternals (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
    Right endpoint <- newEndPoint transport
    let theirAddr = encodeEndPointAddress "127.0.0.1" serverPort 0

    -- Establish a connection to the server
    Right conn1 <- connect endpoint theirAddr ReliableOrdered defaultConnectHints
    send conn1 ["ping"]
    takeMVar serverGotPing

    -- Close the *outgoing* part of the socket only
    sock <- socketBetween internals (address endpoint) theirAddr
    N.shutdown sock N.ShutdownSend

    -- At this point we cannot notice the problem yet so we shouldn't receive an event yet
    Nothing <- timeout 500000 $ receive endpoint

    -- But when we send we find the error
    Left (TransportError SendFailed _) <- send conn1 ["ping"]
    ErrorEvent (TransportError (EventConnectionLost _) _) <- receive endpoint

    -- A call to connect should now re-establish the connection
    Right conn2 <- connect endpoint theirAddr ReliableOrdered defaultConnectHints
    send conn2 ["ping"]
    takeMVar serverGotPing

    -- Again, close the outgoing part of the socket
    sock' <- socketBetween internals (address endpoint) theirAddr
    N.shutdown sock' N.ShutdownSend

    -- We now find the error when we attempt to close the connection
    Nothing <- timeout 500000 $ receive endpoint
    close conn2
    ErrorEvent (TransportError (EventConnectionLost _) _) <- receive endpoint
    Right conn3 <- connect endpoint theirAddr ReliableOrdered defaultConnectHints
    send conn3 ["ping"]
    takeMVar serverGotPing

    -- We repeat once more.
    sock'' <- socketBetween internals (address endpoint) theirAddr
    N.shutdown sock'' N.ShutdownSend

    -- Now we notice the problem when we try to connect
    Nothing <- timeout 500000 $ receive endpoint
    Left (TransportError ConnectFailed _) <- connect endpoint theirAddr ReliableOrdered defaultConnectHints
    ErrorEvent (TransportError (EventConnectionLost _) _) <- receive endpoint
    Right conn4 <- connect endpoint theirAddr ReliableOrdered defaultConnectHints
    send conn4 ["ping"]
    takeMVar serverGotPing

    putMVar clientDone  ()

  readMVar clientDone

testInvalidCloseConnection :: IO ()
testInvalidCloseConnection = do
  Right (transport, internals) <- createTransportExposeInternals (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
  serverAddr <- newEmptyMVar
  clientDone <- newEmptyMVar
  serverDone <- newEmptyMVar

  -- Server
  forkTry $ do
    Right endpoint <- newEndPoint transport
    putMVar serverAddr (address endpoint)

    ConnectionOpened _ _ _ <- receive endpoint

    -- At this point the client sends an invalid request, so we terminate the
    -- connection
    ErrorEvent (TransportError (EventConnectionLost _) _) <- receive endpoint

    putMVar serverDone ()

  -- Client
  forkTry $ do
    Right endpoint <- newEndPoint transport
    let ourAddr = address endpoint

    -- Connect so that we have a TCP connection
    theirAddr  <- readMVar serverAddr
    Right _ <- connect endpoint theirAddr ReliableOrdered defaultConnectHints

    -- Get a handle on the TCP connection and manually send an invalid CloseConnection request
    sock <- socketBetween internals ourAddr theirAddr
    sendMany sock [
        encodeWord32 (encodeControlHeader CloseConnection)
      , encodeWord32 (12345 :: LightweightConnectionId)
      ]

    putMVar clientDone ()

  mapM_ takeMVar [clientDone, serverDone]

testUseRandomPort :: IO ()
testUseRandomPort = do
   testDone <- newEmptyMVar
   forkTry $ do
     Right transport1 <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
     Right ep1        <- newEndPoint transport1
     -- Same as transport1, but is strict in the port.
     Right transport2 <- createTransport (Addressable (TCPAddrInfo "127.0.0.1" "0" (\(!port) -> ("127.0.0.1", port)))) =<< testTCPParametersTLS
     Right ep2        <- newEndPoint transport2
     Right conn1 <- connect ep2 (address ep1) ReliableOrdered defaultConnectHints
     ConnectionOpened _ _ _ <- receive ep1
     putMVar testDone ()
   takeMVar testDone

-- | Verify that if a peer sends an address or data which exceeds the maximum
--   length, that peer's connection will be terminated, but other peers will
--   not be affected.
testMaxLength :: IO ()
testMaxLength = do

  Right serverTransport <- do
    tcpTlsParams <- testTCPParametersTLS
    createTransport (defaultTCPAddr "127.0.0.1" "9998") $ tcpTlsParams {
      -- 17 bytes should fit every valid address at 127.0.0.1.
      -- Port is at most 5 bytes (65536) and id is a base-10 Word32 so
      -- at most 10 bytes. We'll have one client with a 5-byte port to push it
      -- over the chosen limit of 16
      tcpMaxAddressLength = 16
    , tcpMaxReceiveLength = 8
    }

  tcpTlsParams <- testTCPParametersTLS
  Right goodClientTransport <- createTransport (defaultTCPAddr "127.0.0.1" "9999") tcpTlsParams
  Right badClientTransport <- createTransport (defaultTCPAddr "127.0.0.1" "10000") tcpTlsParams

  serverAddress <- newEmptyMVar
  testDone <- newEmptyMVar
  goodClientConnected <- newEmptyMVar
  goodClientDone <- newEmptyMVar
  badClientDone <- newEmptyMVar

  forkTry $ do
    Right serverEp <- newEndPoint serverTransport
    putMVar serverAddress (address serverEp)
    readMVar badClientDone
    ConnectionOpened _ _ _ <- receive serverEp
    Received _ _ <- receive serverEp
    -- Will lose the connection when the good client sends 9 bytes.
    ErrorEvent (TransportError (EventConnectionLost _) _) <- receive serverEp
    readMVar goodClientDone
    putMVar testDone ()

  forkTry $ do
    Right badClientEp <- newEndPoint badClientTransport
    address <- readMVar serverAddress
    -- Wait until the good client connects, then try to connect. It'll fail,
    -- but the good client should still be OK.
    readMVar goodClientConnected
    Left (TransportError ConnectFailed _)
      <- connect badClientEp address ReliableOrdered defaultConnectHints
    closeEndPoint badClientEp
    putMVar badClientDone ()

  forkTry $ do
    Right goodClientEp <- newEndPoint goodClientTransport
    address <- readMVar serverAddress
    Right conn <- connect goodClientEp address ReliableOrdered defaultConnectHints
    putMVar goodClientConnected ()
    -- Wait until the bad client has tried and failed to connect before
    -- attempting a send, to ensure that its failure did not affect us.
    readMVar badClientDone
    Right () <- send conn ["00000000"]
    -- The send which breaches the limit does not appear to fail, but the
    -- (heavyweight) connection is now severed. We can reliably determine that
    -- by receiving.
    Right () <- send conn ["000000000"]
    ErrorEvent (TransportError (EventConnectionLost _) _) <- receive goodClientEp
    closeEndPoint goodClientEp
    putMVar goodClientDone ()

  readMVar testDone
  closeTransport badClientTransport
  closeTransport goodClientTransport
  closeTransport serverTransport

-- | Ensure that an end point closes up OK even if the peer disobeys the
--   protocol.
testCloseEndPoint :: IO ()
testCloseEndPoint = do

  serverAddress <- newEmptyMVar
  serverFinished <- newEmptyMVar

  -- A server which accepts one connection and then attempts to close the
  -- end point.
  forkTry $ do
    Right transport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
    Right ep <- newEndPoint transport
    putMVar serverAddress (address ep)
    ConnectionOpened _ _ _ <- receive ep
    Just () <- timeout 5000000 (closeEndPoint ep)
    putMVar serverFinished ()
    return ()

  -- A nefarious client which connects to the server then stops responding.
  forkTry $ do
    serverAddr <- readMVar serverAddress
    let Just (hostName, serviceName, endPointId) = decodeEndPointAddress serverAddr
    addr:_ <- N.getAddrInfo (Just N.defaultHints) (Just hostName) (Just serviceName)
    sock <- N.socket (N.addrFamily addr) N.Stream N.defaultProtocol
    N.connect sock (N.addrAddress addr)

    -- Version 0x00000000 handshake data.
    let endPointAddress = "127.0.0.1:0:0"
        v0handshake = [
            encodeWord32 endPointId
          , encodeWord32 (fromIntegral (BS.length endPointAddress))
          , endPointAddress
          ]
        -- Version, and total length of the versioned handshake.
        handshake = [
            encodeWord32 0x00000000
          , encodeWord32 (fromIntegral (BS.length (BS.concat v0handshake)))
          ]

    -- Send handshake data to server
    sendMany sock $ handshake ++ v0handshake
    -- Receive ConnectionRequestAccepted response from server
    Just ConnectionRequestAccepted <- decodeConnectionRequestResponse <$> recvWord32 sock

    -- Initiate client TLS handshake
    tlsClientParams <- testTLSClientParams serverAddr
    tlsCtx <- tlsHandshakeClient tlsClientParams sock (encodeEndPointAddress "127.0.0.1" "0" 0)

    sendMany sock
      [ -- Create a lightweight connection.
        encodeWord32 (encodeControlHeader CreatedNewConnection)
      , encodeWord32 1024
      ]

    readMVar serverFinished
    N.close sock

  readMVar serverFinished

-- | Ensure that if the peer's claimed host doesn't match its actual host,
--   the connection is rejected (when tcpCheckPeerHost is enabled).
testCheckPeerHostReject :: IO ()
testCheckPeerHostReject = do

  tlsParams <- testTCPParametersTLS
  let params = tlsParams { tcpCheckPeerHost = True }
  Right transport1 <- createTransport (defaultTCPAddr "127.0.0.1" "0") params
  -- This transport claims 127.0.0.2 as its host, but connections from it to
  -- an EndPoint on transport1 will show 127.0.0.1 as the socket's source host.
  Right transport2 <- createTransport (Addressable (TCPAddrInfo "127.0.0.1" "0" ((,) "127.0.0.2"))) =<< testTCPParametersTLS

  Right ep1 <- newEndPoint transport1
  Right ep2 <- newEndPoint transport2

  Left err <- connect ep2 (address ep1) ReliableOrdered defaultConnectHints

  TransportError ConnectFailed _ <- return err

  return ()

-- | Ensure that if peer host checking works through name resolution: if the
--   peer claims "localhost", and connects to a transport also on localhost,
--   it should be accepted.
testCheckPeerHostResolve :: IO ()
testCheckPeerHostResolve = do

  tlsParams <- testTCPParametersTLS
  let params = tlsParams { tcpCheckPeerHost = True }
  Right transport1 <- createTransport (defaultTCPAddr "127.0.0.1" "0") params
  -- EndPoints on this transport have addresses with "localhost" host part.
  Right transport2 <- createTransport (Addressable (TCPAddrInfo "127.0.0.1" "0" ((,) "localhost"))) tlsParams

  Right ep1 <- newEndPoint transport1
  Right ep2 <- newEndPoint transport2

  Right conn <- connect ep2 (address ep1) ReliableOrdered defaultConnectHints

  close conn

  return ()

-- | Test that an unreachable EndPoint can use its own address to connect
-- to itself.
testUnreachableSelfConnect :: IO ()
testUnreachableSelfConnect = do
  Right transport <- createTransport Unaddressable =<< testTCPParametersTLS
  Right ep <- newEndPoint transport
  Right conn <- connect ep (address ep) ReliableOrdered defaultConnectHints
  ConnectionOpened connid ReliableOrdered _ <- receive ep
  Right () <- send conn ["ping"]
  Received connid' bytes <- receive ep
  _ <- close conn
  ConnectionClosed connid'' <- receive ep
  closeEndPoint ep
  closeTransport transport

-- | Test that
--
-- 1. Connecting to an unreachable EndPoint's address gives ConnectFailed
-- 2. An unreachable EndPoint can successfully connect to a reachable EndPoint
-- 3. The address given in the ConnectionOpened event at the reachable EndPoint
--    can be used to connect to the unreachable EndPoint, so long as there is
--    at least one lightweight connection open between the two.
testUnreachableConnect :: IO ()
testUnreachableConnect = do
  Right rtransport <- createTransport (defaultTCPAddr "127.0.0.1" "0") =<< testTCPParametersTLS
  Right utransport <- createTransport Unaddressable =<< testTCPParametersTLS
  Right rep <- newEndPoint rtransport
  Right uep <- newEndPoint utransport
  -- Reachable endpoint connects to the unreachable endpoint, but it fails.
  -- NB ConnectNotFound isn't the error; that would mean the address makes
  -- sense but the host could not be found.
  Left (TransportError ConnectFailed _) <- connect rep (address uep) ReliableOrdered defaultConnectHints
  -- Unreachable endpoint connects to the reachable endpoint.
  Right conn <- connect uep (address rep) ReliableOrdered defaultConnectHints
  -- Reachable endpoint now has an address at which it can connect to the
  -- unreachable
  ConnectionOpened _ _ addr <- receive rep
  Right conn' <- connect rep addr ReliableOrdered defaultConnectHints
  ConnectionOpened _ _ addr' <- receive uep
  close conn
  ConnectionClosed _ <- receive rep
  close conn'
  ConnectionClosed _ <- receive uep
  closeEndPoint rep
  closeEndPoint uep
  closeTransport rtransport
  closeTransport utransport

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  tcpResult <- tryIO $ runTests
           [ ("Use random port",        testUseRandomPort)
           , ("EarlyDisconnect",        testEarlyDisconnect)
           , ("EarlyCloseSocket",       testEarlyCloseSocket)
           , ("IgnoreCloseSocket",      testIgnoreCloseSocket)
           , ("BlockAfterCloseSocket",  testBlockAfterCloseSocket)
           , ("UnnecessaryConnect",     testUnnecessaryConnect 10)
           , ("InvalidAddress",         testInvalidAddress)
           , ("InvalidConnect",         testInvalidConnect)
           , ("Many",                   testMany)
           , ("BreakTransport",         testBreakTransport)
           , ("Reconnect",              testReconnect)
           , ("UnidirectionalError",    testUnidirectionalError)
           , ("InvalidCloseConnection", testInvalidCloseConnection)
           , ("MaxLength",              testMaxLength)
           , ("CloseEndPoint",          testCloseEndPoint)
           , ("CheckPeerHostReject",    testCheckPeerHostReject)
           , ("CheckPeerHostResolve",   testCheckPeerHostResolve)
           , ("UnreachableSelfConnect", testUnreachableSelfConnect)
           , ("UnreachableConnect",     testUnreachableConnect)
           ]
  -- Run the generic tests even if the TCP specific tests failed..
  tcpTLSParams <- testTCPParametersTLS
  testTransport (either (Left . show) (Right) <$>
    createTransport (defaultTCPAddr "127.0.0.1" "0") tcpTLSParams)
  -- ..but if the generic tests pass, still fail if the specific tests did not
  case tcpResult of
    Left err -> throwIO err
    Right () -> return ()
