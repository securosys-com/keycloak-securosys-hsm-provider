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
package com.securosys.hsm.dto;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
@Data
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class PolicyDto extends ModifyPolicyDto {

    private KeyStatus keyStatus;

    public KeyStatus getKeyStatus() {
        return keyStatus;
    }

    public void setKeyStatus(KeyStatus keyStatus) {
        this.keyStatus = keyStatus;
    }

    @Data
    public static class KeyStatus {

        private Boolean blocked;

    }
}
