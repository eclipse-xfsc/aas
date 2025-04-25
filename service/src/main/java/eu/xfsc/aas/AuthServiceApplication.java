/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.xfsc.aas;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The Application class.
 */
@SpringBootApplication
public class AuthServiceApplication {

    private final static Logger log = LoggerFactory.getLogger(AuthServiceApplication.class);
    
    /**
     * The main Method.
     *
     * @param args the args for the main method
     */
    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
        log.info("env variables: {}", System.getProperties());
    }
}
