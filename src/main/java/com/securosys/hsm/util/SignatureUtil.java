/**
 * Copyright (c)2025 Securosys SA, authors: Tomasz Madej
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * <p>
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 **/
package com.securosys.hsm.util;

import com.securosys.primus.jce.PrimusEncoding;
import com.securosys.primus.jce.encoding.DERObject;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

public class SignatureUtil {
    public static byte[] extractRSfromDERSignature(byte[] sig) {
        byte[] underifiedSignature = PrimusEncoding.underifyRS(sig);
        byte[] r = Arrays.copyOfRange(underifiedSignature, 0, underifiedSignature.length / 2);
        byte[] s = Arrays.copyOfRange(underifiedSignature, underifiedSignature.length / 2, underifiedSignature.length);
        return cat(r, s);
    }



    public static byte[] cat(byte[] a, byte[] b) {
        if (b == null) {
            return a;
        } else if (a == null) {
            return b;
        } else if (b.length == 0) {
            return a;
        } else if (a.length == 0) {
            return b;
        }
        final byte[] bytes = new byte[a.length + b.length];
        System.arraycopy(a, 0, bytes, 0, a.length);
        System.arraycopy(b, 0, bytes, a.length, b.length);
        return bytes;
    }
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    static byte[] unpadPad(final byte[] bytes, final int length) {
        byte[] b = bytes;
        // unpad
        while (b != null && b.length > 1 && b[0] == 0 && b.length > length) {
            b = Arrays.copyOfRange(b, 1, b.length);
        }
        // pad
        while (b != null && b.length < length) {
            b = cat(new byte[1], b);
        }
        return b;
    }

}