/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp.messages;

/**
 *
 * @author 07721825741
 */
public enum PKIFailureInfoEnum {

    badAlg(0, "unrecognized or unsupported Algorithm Identifier"),
    badRequest(2, "transaction not permitted or supported"),
    badDataFormat(5, "the data submitted has the wrong format"),
    timeNotAvailable(14, "the TSA’s time source is not available"),
    unacceptedPolicy(15, "the requested TSA policy is not supported by the TSA"),
    unacceptedExtension(16, "the requested extension is not supported by the TSA"),
    addInfoNotAvailable(17, "the additional information requested could not be understoodor is not available"),
    systemFailure(25, "the request cannot be handled due to system failure");
    private int id;
    private String message;

    private PKIFailureInfoEnum(int id, String message) {
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
