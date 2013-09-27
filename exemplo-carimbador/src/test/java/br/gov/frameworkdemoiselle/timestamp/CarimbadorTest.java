/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp;

import junit.framework.TestCase;

/**
 *
 * @author 07721825741
 */
public class CarimbadorTest extends TestCase {

    public CarimbadorTest(String testName) {
        super(testName);
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Test of carimbar method, of class Carimbador.
     */
    public void testCarimbar() {
        System.out.println("carimbar");
        Carimbador instance = new Carimbador();
        instance.carimbar(null);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of validar method, of class Carimbador.
     */
    public void testValidar() {
        System.out.println("validar");
        Carimbador instance = new Carimbador();
        boolean expResult = false;
        boolean result = instance.validar();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
}
