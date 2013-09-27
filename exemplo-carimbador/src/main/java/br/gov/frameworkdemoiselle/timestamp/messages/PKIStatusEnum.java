/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp.messages;

/**
 *
 * @author 07721825741
 */
public enum PKIStatusEnum {

    granted(0, "Texto"),
    grantedWithMods(1, ""),
    rejection(2, ""),
    waiting(3, ""),
    revocationWarning(4, ""),
    revocationNotification(5, "");
    private int id;
    private String message;

    private PKIStatusEnum(int id, String message) {
        this.id = id;
        this.message = message;
    }

    public int getId() {
        return id;
    }

    public String getMessage() {
        return message;
    }
}
