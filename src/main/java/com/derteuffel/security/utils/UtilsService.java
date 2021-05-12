/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.derteuffel.security.utils;

import java.util.Base64;

/**
 *
 * @author Nappster-SPRINT-PAY
 */
public class UtilsService {
    
    public static String[] extractCredentials(String authString) {

        String[] credentials = null;
        // Header is in the format "Basic 5tyc0uiDat4"
        // We need to extract data before decoding it back to original string
        if (!authString.isEmpty()) {
            String[] authParts = authString.split("\\s+");
            String authInfo = authParts[1];
            // Decode the data back to original string
            byte[] decode = Base64.getDecoder().decode(authInfo.getBytes());
            String decodeString = new String(decode);

            credentials = decodeString.split(":");
        }

        return credentials;
    }
    
}
