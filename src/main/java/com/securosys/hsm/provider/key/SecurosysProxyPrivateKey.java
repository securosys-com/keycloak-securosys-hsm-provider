/**
 * Copyright (c)2026 Securosys SA, authors: Tomasz Madej
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

package com.securosys.hsm.provider.key;

import com.securosys.hsm.dto.Config;
import lombok.Data;

import java.security.PrivateKey;

@Data
public class SecurosysProxyPrivateKey implements PrivateKey {
    private final String algorithm;
    private String label;
    private String password;
    private Config hsmConfig;

    public SecurosysProxyPrivateKey(String label, String algorithm, Config hsmConfig) {
        this.label = label;
        this.algorithm = algorithm;
        this.hsmConfig = hsmConfig;
    }

    public String getAlias() { return label; }

    @Override
    public String getAlgorithm() { return this.algorithm; } // lub Twój algorytm

    @Override
    public String getFormat() { return null; } // Ważne: nie ma formatu (nieeksportowalny)

    @Override
    public byte[] getEncoded() { return null; } // Ważne: nie zwraca bajtów
}