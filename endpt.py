#!/usr/bin/env python3

# Project     : pyzrtp
# Copyright (C) 2017 Orange
# All rights reserved.
# This software is distributed under the terms and conditions of the 'BSD 3-Clause'
# license which can be found in the file 'LICENSE' in this package distribution.

import socket
import os
from struct import unpack, pack
import time
import base64
import subprocess
import logging
import asyncio
import sys

from binascii import hexlify
from binascii import unhexlify as ux

import hashlib
import hmac

import zrtp.protocol

import zrtp.auth
import zrtp.hash
import zrtp.cipher
import zrtp.pubkey
import zrtp.sas

# derive hash chain from H0
# values will be used to authenticate sent messages
def derive_hashchain(h0):
  h = h0
  chain = [h0]

  for i in range(3):
    h = hashlib.sha256(h).digest()
    chain.append(h)

  return chain

assert(derive_hashchain(ux('06fa3b98d71b2d4d2037886f9417377b312dd17ddd769ef7b651dcc3a661d382')) == [
  ux('06fa3b98d71b2d4d2037886f9417377b312dd17ddd769ef7b651dcc3a661d382'),
  ux('e54ed85bdbd82feeb3cc8e6fab43d9c23c049095a45a534d9788ce83fe92e275'),
  ux('6d6f62d8123e0a175d7d85f811cb2200046961da776c46feae87e2b454c96fc5'),
  ux('5ecde82016ea439b570ef0a854667270b7e2792419b38bbbe07e14ec51ac7e93')
])

# authenticate ZRTP message
def default_authenticate(key, data):
  m = hmac.new(key, digestmod=hashlib.sha256)
  m.update(data)
  return m.digest()[:8]

assert(default_authenticate(
  ux('6d6f62d8123e0a175d7d85f811cb2200046961da776c46feae87e2b454c96fc5'),
  ux('505a001d48656c6c6f202020312e3130474e55205a52545020342e352e3020205ecde82016ea439b570ef0a854667270b7e2792419b38bbbe07e14ec51ac7e9354f2b6af22cca341ee5845060002202153333834534b4e3332465333414553334448336b4543333842323536')) == ux('379b200f0fab4d3f'))

logging.basicConfig(level=logging.DEBUG,
  format='%(asctime)s %(message)s', stream=sys.stdout)
log = logging.getLogger('main')

loop = asyncio.get_event_loop()

# act as responder
# set the Passive flag in Hello message
class ZrtpEndpoint(asyncio.DatagramProtocol):
  def datagram_received(self, data, addr):
    self.inq.put_nowait(data)

  def __init__(self, zid=None, H0=None):
    self.transport = None
    self.dst = None
    self.inq = asyncio.Queue()

    self.seqno = 0

    self.ssrc = 0xdeadbeef

    if zid is None:
      self.zidr = os.urandom(12)
    else:
      self.zidr = zid
    assert(len(self.zidr) == 12)

    if H0 is None:
      self.H = derive_hashchain(b'omg wtf!'*4)
    else:
      self.H = derive_hashchain(H0)

    self.zidi = None

    self.history = {}

  @asyncio.coroutine
  def prepare(self):
    # generate Hello message
    hello = zrtp.protocol.Hello(
      version=b'1.10',
      clt=b'OMG WTF!OMG WTF!',
      h3=self.H[3],
      zid=self.zidr,
      S=0,
      M=0,
      P=1,
      hashes=[b'S256'],
      ciphers=[b'AES3'],
      auths=[b'HS32'],
      keys=[b'DH3k'],
      sass=[b'B256'],
      mac=0
    )

    data = zrtp.protocol.encode_hello(hello)
    self.hello = data[:-8] + default_authenticate(self.H[2], data[:-8])
    self.hello_hash = hexlify(hashlib.sha256(self.hello).digest())

    self.transport, self.protocol = yield from loop.create_datagram_endpoint(lambda: self, local_addr=('198.51.100.1', 20000))

  @asyncio.coroutine
  def start(self):
    self.rs1 = os.urandom(8)
    self.rs2 = os.urandom(8)
    self.auxsecret = os.urandom(8)
    self.pbxsecret = os.urandom(8)

    self.send(self.hello)
    log.debug('  ZRTP -> Hello')

    # store received Hello for future computations
    self.history['Hello'] = self.hello

    hello_received = False
    hello_ack_received = False
    while not hello_received or not hello_ack_received:
      pkt = yield from self.recv()
      if type(pkt.msg) == zrtp.protocol.HelloAck:
        hello_ack_received = True
        log.debug('  ZRTP <- HelloAck')
      elif type(pkt.msg) == zrtp.protocol.Hello:
        self.zidi = pkt.msg.zid

        data = zrtp.protocol.encode_hello_ack()
        self.send(data)
        hello_received = True
        log.debug('  ZRTP <- Hello')

    pkt = yield from self.recv()
    assert(type(pkt.msg) == zrtp.protocol.DHCommit)
    log.debug('  ZRTP <- DHCommit')
    self.history['Commit'] = pkt.raw

    hash_alg = zrtp.hash.get(pkt.msg.hash)
    cipher_alg = zrtp.cipher.get(pkt.msg.cipher)

    auth_alg = zrtp.auth.get(pkt.msg.auth)
    # this is an instance !!!
    self.key_xchg = zrtp.pubkey.get(pkt.msg.key)
    sas_alg = zrtp.sas.get(pkt.msg.sas)

    def MAC(key, data):
      m = auth_alg(key)
      m.update(data)
      return m.digest()

    KDF = zrtp.hash.get_kdf(hash_alg)

    self.rs1IDr = MAC(self.rs1, b'Responder')[:8]
    self.rs2IDr = MAC(self.rs2, b'Responder')[:8]
    self.auxsecretIDr = MAC(self.auxsecret, self.H[3])[:8]
    self.pbxsecretIDr = MAC(self.pbxsecret, b'Responder')[:8]

    pvr = self.key_xchg.generate_key()

    dhpart1 = zrtp.protocol.DHPart1(
      h1 = self.H[1],
      rs1idr = self.rs1IDr,
      rs2idr = self.rs2IDr,
      auxsecretidr = self.auxsecretIDr,
      pbxsecretidr = self.pbxsecretIDr,
      pvr = pvr,
      mac = 0,
    )

    # authenticate and send it
    data = zrtp.protocol.encode_dhpart1(dhpart1)
    authenticated_data = data[:-8] + default_authenticate(self.H[0], data[:-8])[:8]
    self.send(authenticated_data)
    log.debug('  ZRTP -> DHPart1')
    self.history['DHPart1'] = authenticated_data

    pkt = yield from self.recv()
    assert(type(pkt.msg) == zrtp.protocol.DHPart2)
    log.debug('  ZRTP <- DHPart2')
    self.history['DHPart2'] = pkt.raw

    # DHresult
    dhresult = self.key_xchg.shared_secret(pkt.msg.pvi)

    # total_hash
    m = hashlib.sha256()
    m.update(self.history['Hello'])
    m.update(self.history['Commit'])
    m.update(self.history['DHPart1'])
    m.update(self.history['DHPart2'])
    total_hash = m.digest()

    # KDF_Context
    KDF_Context = self.zidi + self.zidr + total_hash

    # suppose no secrets are shared between us
    s1 = b''
    s2 = b''
    s3 = b''

    # s0
    m = hash_alg()
    m.update(pack('!I', 1))
    m.update(dhresult)
    m.update(b'ZRTP-HMAC-KDF')
    m.update(self.zidi)
    m.update(self.zidr)
    m.update(total_hash)

    m.update(pack('!I', len(s1)) + s1)
    m.update(pack('!I', len(s2)) + s2)
    m.update(pack('!I', len(s3)) + s3)
    s0 = m.digest()

    # SAS
    sashash = KDF(s0, b'SAS', KDF_Context, 256)
    sasval = sashash[:4]
    log.debug('  ZRTP SAS %s' % sas_alg(sasval))

    # 256 for SHA256, shall be the negotiated hash length
    mackeyi = KDF(s0, b'Initiator HMAC key', KDF_Context, 256)
    mackeyr = KDF(s0, b'Responder HMAC key', KDF_Context, 256)

    zrtpkeyi = KDF(s0, b'Initiator ZRTP key', KDF_Context, cipher_alg.keybits)
    zrtpkeyr = KDF(s0, b'Responder ZRTP key', KDF_Context, cipher_alg.keybits)

    # SRTP keys
    srtpkeyi = KDF(s0, b'Initiator SRTP master key', KDF_Context, cipher_alg.keybits)
    srtpkeyr = KDF(s0, b'Responder SRTP master key', KDF_Context, cipher_alg.keybits)

    srtpsalti = KDF(s0, b'Initiator SRTP master salt', KDF_Context, 112)
    srtpsaltr = KDF(s0, b'Responder SRTP master salt', KDF_Context, 112)

    # retained secrets
    rs1 = KDF(s0, b'retained secret', KDF_Context, 256)

    # set Verified flag
    confirmation = zrtp.protocol.Confirmation(
      h0 = self.H[0],
      E = 0,
      V = 1,
      A = 0,
      D = 0,
      cache_expiration = 0xffffffff,
    )
    data = zrtp.protocol.encode_confirmation(confirmation)

    confirmation = zrtp.protocol.Confirmation(h0=self.H[0], E=0, V=1, A=0, D=0, cache_expiration=0xffffffff)
    data = zrtp.protocol.encode_confirmation(confirmation)

    cfb_iv = b'\x00'*16
    encrypted_confirmation = cipher_alg.constructor(zrtpkeyr, cfb_iv).encrypt(data)
    assert(len(encrypted_confirmation) == len(data))

    confirm_mac = MAC(mackeyr, encrypted_confirmation)[:8]

    confirm1 = zrtp.protocol.Confirm(
      confirm_mac = confirm_mac,
      cfb_iv = cfb_iv,
      encrypted = encrypted_confirmation,
    )

    data = zrtp.protocol.encode_confirm1(confirm1)
    self.send(data)
    log.debug('  ZRTP -> Confirm1')

    pkt = yield from self.recv()
    assert(type(pkt.msg) == zrtp.protocol.Confirm)
    log.debug('  ZRTP <- Confirm2')

    # check received, verify authenticity
    # decrypt and verify hash chain

    data = zrtp.protocol.encode_conf2ack()
    self.send(data)
    log.debug('  ZRTP -> Conf2ACK')
 
    assert(len(srtpsalti) == 14)
    assert(len(srtpsaltr) == 14)

    srtpi = hexlify(srtpkeyi + srtpsalti)
    log.debug('SRTP(Initiator) = %s' % srtpi.decode('utf-8'))
    srtpr = hexlify(srtpkeyr + srtpsaltr)
    log.debug('SRTP(Responder) = %s' % srtpr.decode('utf-8'))

  def send(self, m):
    pkt = zrtp.protocol.Pkt(
      version=0,
      padding=0,
      extension=1,
      seqno=self.seqno,
      cookie=0x5a525450,
      src=self.ssrc,
      raw=m
    )

    assert(self.transport)
    assert(self.dst)

    self.transport.sendto(zrtp.protocol.encode(pkt), self.dst)

    self.seqno += 1

  @asyncio.coroutine
  def recv(self):
    while True:
      data = yield from asyncio.wait_for(self.inq.get(), 5.0)
      pkt = zrtp.protocol.decode(data)
      if pkt:
        return pkt
