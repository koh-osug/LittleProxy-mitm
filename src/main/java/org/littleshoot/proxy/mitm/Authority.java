package org.littleshoot.proxy.mitm;

import java.io.File;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.With;

/**
 * Information for the certification authority.
 * 
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
@With
public class Authority {

    private File keyStoreDir = new File(".");

    private String alias = "littleproxy-mitm";

    private char[] password = "Be Your Own Lantern".toCharArray();

    private String organization =  "LittleProxy-mitm";

    private String commonName = organization + ", describe proxy here";;

    private String organizationalUnitName = "Certificate Authority";

    private String certOrganization = organization;

    private String certOrganizationalUnitName = organization
            + ", describe proxy purpose here, since Man-In-The-Middle is bad normally.";

    public File aliasFile(String fileExtension) {
        return new File(keyStoreDir, alias + fileExtension);
    }

}
