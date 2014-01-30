/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

package com.facebook.crypto;

import com.facebook.crypto.cipher.NativeGCMCipher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Helper functions for tests to serialize and de-serialize crypto data.
 */
public class CryptoSerializerHelper {

  public static byte[] cipherText(byte[] cipheredData) {
    return Arrays.copyOfRange(cipheredData,
        NativeGCMCipher.IV_LENGTH + 2,
        cipheredData.length - NativeGCMCipher.TAG_LENGTH);
  }

  public static byte[] tag(byte[] cipheredData) {
    return Arrays.copyOfRange(cipheredData,
        cipheredData.length - NativeGCMCipher.TAG_LENGTH,
        cipheredData.length);
  }

  public static byte[] createCipheredData(byte[] iv, byte[] cipherText, byte[] tag) throws IOException {
    ByteArrayOutputStream cipheredData = new ByteArrayOutputStream();
    cipheredData.write(VersionCodes.CIPHER_SERALIZATION_VERSION);
    cipheredData.write(VersionCodes.CIPHER_ID);
    cipheredData.write(iv);
    cipheredData.write(cipherText);
    cipheredData.write(tag);
    return cipheredData.toByteArray();
  }

  public static byte[] createMacData(byte[] data, byte[] macBytes) throws IOException {
    ByteArrayOutputStream dataWithMac = new ByteArrayOutputStream();
    dataWithMac.write(VersionCodes.MAC_SERIALIZATION_VERSION);
    dataWithMac.write(VersionCodes.MAC_ID);
    dataWithMac.write(data);
    dataWithMac.write(macBytes);
    return  dataWithMac.toByteArray();
  }

  public static byte[] getMacTag(byte[] macData, int macLength) {
    return Arrays.copyOfRange(macData, macData.length - macLength, macData.length);
  }

  public static byte[] getOriginalDataFromMacData(byte[] macData, int macLength) {
    return Arrays.copyOfRange(macData, 2, macData.length - macLength);
  }
}
