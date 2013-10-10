/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.gov.frameworkdemoiselle.timestamp.applet;

import br.gov.frameworkdemoiselle.certificate.CertificateValidatorException;
import br.gov.frameworkdemoiselle.certificate.applet.config.AppletConfig;
import br.gov.frameworkdemoiselle.certificate.applet.handler.PinCallbackHandler;
import br.gov.frameworkdemoiselle.certificate.applet.tiny.Item;
import br.gov.frameworkdemoiselle.certificate.applet.view.ListaCertificadosModel;
import br.gov.frameworkdemoiselle.certificate.criptography.DigestAlgorithmEnum;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.DriverNotAvailableException;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.InvalidPinException;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.KeyStoreLoader;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.KeyStoreLoaderException;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.PKCS11NotFoundException;
import br.gov.frameworkdemoiselle.certificate.keystore.loader.factory.KeyStoreLoaderFactory;
import br.gov.frameworkdemoiselle.timestamp.TimestampGenerator;
import br.gov.frameworkdemoiselle.timestamp.enumeration.ConnectionType;
import br.gov.frameworkdemoiselle.timestamp.utils.Utils;
import java.awt.Cursor;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 *
 * @author 07721825741
 */
public class App extends javax.swing.JApplet {

    private KeyStore keystore = null;

    /**
     * Initializes the applet App
     */
    @Override
    public void init() {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(App.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(App.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(App.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(App.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the applet */
        try {
            java.awt.EventQueue.invokeAndWait(new Runnable() {
                public void run() {
                    initComponents();
                    loadCertificates();
                }
            });
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void loadCertificates() {
        ListaCertificadosModel listaCertificadosModel = new ListaCertificadosModel();
        listaCertificadosModel.populate(this.getKeyStore());
        tableCertificados.setModel(listaCertificadosModel);

        if (tableCertificados.getRowCount() == 0) {
            buttonCarimbar.setEnabled(false);
        } else {
            tableCertificados.setRowSelectionInterval(0, 0);
        }
    }

    /**
     * Retorna o keystore do dispositivo a partir do valor de pin
     */
    public KeyStore getKeyStore() {
        try {
            Cursor hourGlassCursor = new Cursor(Cursor.WAIT_CURSOR);
            setCursor(hourGlassCursor);
            KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
            loader.setCallbackHandler(new PinCallbackHandler());
            keystore = loader.getKeyStore();
            return keystore;

        } catch (DriverNotAvailableException e) {
            showError(AppletConfig.MESSAGE_ERROR_DRIVER_NOT_AVAILABLE.getValue());
        } catch (PKCS11NotFoundException e) {
            showError(AppletConfig.MESSAGE_ERROR_PKCS11_NOT_FOUND.getValue());
        } catch (CertificateValidatorException e) {
            showError(AppletConfig.MESSAGE_ERROR_LOAD_TOKEN.getValue());
        } catch (InvalidPinException e) {
            showError(AppletConfig.MESSAGE_ERROR_INVALID_PIN.getValue());
        } catch (KeyStoreLoaderException ke) {
            showError(ke.getMessage());
        } catch (Exception ex) {
            showError(AppletConfig.MESSAGE_ERROR_UNEXPECTED.getValue());
        } finally {
            Cursor hourGlassCursor = new Cursor(Cursor.DEFAULT_CURSOR);
            setCursor(hourGlassCursor);
        }
        return null;
    }

    /**
     * Exibe as mensagens de erro
     *
     * @param message
     */
    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, AppletConfig.LABEL_DIALOG_OPTION_PANE_TITLE.getValue(), JOptionPane.ERROR_MESSAGE);
    }

    private byte[] readContent(String arquivo) throws FileNotFoundException, IOException {
        byte[] result = null;

        File file = new File(arquivo);
        FileInputStream is = new FileInputStream(file);
        result = new byte[(int) file.length()];
        is.read(result);
        is.close();
        return result;
    }

    private void writeContent(byte[] conteudo, String arquivo) throws FileNotFoundException, IOException {
        File file = new File(arquivo);
        FileOutputStream os = new FileOutputStream(file);
        os.write(conteudo);
        os.flush();
        os.close();
    }

    /**
     * Retorna o alias
     *
     * @return
     */
    public String getAlias() {
        if (tableCertificados.getModel().getRowCount() != 0) {
            int row = tableCertificados.getSelectedRow();
            Item item = (Item) tableCertificados.getModel().getValueAt(row, 0);
            return item.getAlias();
        } else {
            return "";
        }
    }

    /**
     * This method is called from within the init() method to initialize the
     * form. WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        chooser = new javax.swing.JFileChooser();
        tabbedPane = new javax.swing.JTabbedPane();
        panelCarimbador = new javax.swing.JPanel();
        scrollPaneInformacoes = new javax.swing.JScrollPane();
        textAreaRequisicaoCarimboTempo = new javax.swing.JTextArea();
        scrollPaneCertificados = new javax.swing.JScrollPane();
        tableCertificados = new javax.swing.JTable();
        labelRegistroEventos = new javax.swing.JLabel();
        labelCertificadosDigitais = new javax.swing.JLabel();
        buttonCarimbar = new javax.swing.JButton();
        panelValidador = new javax.swing.JPanel();
        buttonValidar = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        scrollPaneCertificados2 = new javax.swing.JScrollPane();
        textAreaValidacaoCarimboTempo = new javax.swing.JTextArea();

        tabbedPane.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        panelCarimbador.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        textAreaRequisicaoCarimboTempo.setEditable(false);
        textAreaRequisicaoCarimboTempo.setColumns(20);
        textAreaRequisicaoCarimboTempo.setRows(5);
        scrollPaneInformacoes.setViewportView(textAreaRequisicaoCarimboTempo);

        tableCertificados.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null},
                {null, null, null, null}
            },
            new String [] {
                "Title 1", "Title 2", "Title 3", "Title 4"
            }
        ));
        scrollPaneCertificados.setViewportView(tableCertificados);

        labelRegistroEventos.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        labelRegistroEventos.setText("Informações do carimbo de tempo");

        labelCertificadosDigitais.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        labelCertificadosDigitais.setText("Certificados Digitais");

        buttonCarimbar.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        buttonCarimbar.setIcon(new javax.swing.ImageIcon(getClass().getResource("/br/gov/frameworkdemoiselle/timestamp/applet/certificate2_clock.png"))); // NOI18N
        buttonCarimbar.setText("Carimbar Documento");
        buttonCarimbar.setToolTipText("Solicita um carimbo de tempo");
        buttonCarimbar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonCarimbarActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout panelCarimbadorLayout = new javax.swing.GroupLayout(panelCarimbador);
        panelCarimbador.setLayout(panelCarimbadorLayout);
        panelCarimbadorLayout.setHorizontalGroup(
            panelCarimbadorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelCarimbadorLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelCarimbadorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(scrollPaneCertificados, javax.swing.GroupLayout.DEFAULT_SIZE, 589, Short.MAX_VALUE)
                    .addGroup(panelCarimbadorLayout.createSequentialGroup()
                        .addGroup(panelCarimbadorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(labelRegistroEventos)
                            .addComponent(labelCertificadosDigitais)
                            .addComponent(buttonCarimbar))
                        .addGap(0, 353, Short.MAX_VALUE))
                    .addComponent(scrollPaneInformacoes))
                .addContainerGap())
        );
        panelCarimbadorLayout.setVerticalGroup(
            panelCarimbadorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, panelCarimbadorLayout.createSequentialGroup()
                .addGap(6, 6, 6)
                .addComponent(labelCertificadosDigitais)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(scrollPaneCertificados, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(labelRegistroEventos)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(scrollPaneInformacoes, javax.swing.GroupLayout.DEFAULT_SIZE, 193, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(buttonCarimbar, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        tabbedPane.addTab("Requisitar Carimbo", panelCarimbador);

        panelValidador.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        buttonValidar.setIcon(new javax.swing.ImageIcon(getClass().getResource("/br/gov/frameworkdemoiselle/timestamp/applet/certificate2_checkmark.png"))); // NOI18N
        buttonValidar.setText("Verificar Carimbo de Tempo");
        buttonValidar.setToolTipText("Verifica um carimbo de tempo");
        buttonValidar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                buttonValidarActionPerformed(evt);
            }
        });

        jLabel1.setFont(new java.awt.Font("Dialog", 0, 12)); // NOI18N
        jLabel1.setText("Informações do carimbo de tempo");

        textAreaValidacaoCarimboTempo.setColumns(20);
        textAreaValidacaoCarimboTempo.setRows(5);
        scrollPaneCertificados2.setViewportView(textAreaValidacaoCarimboTempo);

        javax.swing.GroupLayout panelValidadorLayout = new javax.swing.GroupLayout(panelValidador);
        panelValidador.setLayout(panelValidadorLayout);
        panelValidadorLayout.setHorizontalGroup(
            panelValidadorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelValidadorLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(panelValidadorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(scrollPaneCertificados2, javax.swing.GroupLayout.DEFAULT_SIZE, 589, Short.MAX_VALUE)
                    .addGroup(panelValidadorLayout.createSequentialGroup()
                        .addGroup(panelValidadorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel1)
                            .addComponent(buttonValidar))
                        .addGap(0, 313, Short.MAX_VALUE)))
                .addContainerGap())
        );
        panelValidadorLayout.setVerticalGroup(
            panelValidadorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(panelValidadorLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(scrollPaneCertificados2, javax.swing.GroupLayout.DEFAULT_SIZE, 344, Short.MAX_VALUE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(buttonValidar, javax.swing.GroupLayout.PREFERRED_SIZE, 60, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );

        tabbedPane.addTab("Verificar Carimbo", panelValidador);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(tabbedPane)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(tabbedPane)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private void buttonCarimbarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonCarimbarActionPerformed
        //Limpa a tela do log de eventos
        textAreaRequisicaoCarimboTempo.setText("");
        buttonCarimbar.setEnabled(false);
        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

        chooser = new JFileChooser();
        int returnVal = chooser.showOpenDialog(panelCarimbador);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            try {
                String name = chooser.getSelectedFile().getName();
                String workdir = chooser.getSelectedFile().getParent();
                byte[] content = Utils.readContent(chooser.getSelectedFile().getAbsolutePath());

                TimestampGenerator timestampGen = new TimestampGenerator();
                byte[] pedido = timestampGen.createRequest(content, keystore, this.getAlias(), DigestAlgorithmEnum.SHA_256);
                Utils.writeContent(pedido, workdir.concat("/").concat(name).concat(".tsq"));
                byte[] resposta = timestampGen.doTimestamp(pedido, ConnectionType.SOCKET);
                Utils.writeContent(resposta, workdir.concat("/").concat(name).concat(".tsr"));
                textAreaRequisicaoCarimboTempo.append(timestampGen.getTimestamp().toString());

                JOptionPane.showMessageDialog(panelCarimbador, "Carimbo de Tempo obtido com sucesso.", "Mensagem", JOptionPane.INFORMATION_MESSAGE);

            } catch (Exception e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(panelCarimbador, e.getMessage(), "Mensagem", JOptionPane.ERROR_MESSAGE);
            } finally {
                buttonCarimbar.setEnabled(true);
                setCursor(null); //turn off the wait cursor
            }
        } else {
            JOptionPane.showMessageDialog(panelCarimbador, "A operacao foi cancelada pelo usuario.", "Mensagem", JOptionPane.INFORMATION_MESSAGE);
            buttonCarimbar.setEnabled(true);
            setCursor(null); //turn off the wait cursor
        }
    }//GEN-LAST:event_buttonCarimbarActionPerformed

    private void buttonValidarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_buttonValidarActionPerformed
//Limpa a tela do log de eventos
        textAreaValidacaoCarimboTempo.setText("");
        buttonValidar.setEnabled(false);
        setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

        chooser = new JFileChooser();
        FileNameExtensionFilter tsrFilter = new FileNameExtensionFilter("Time Stamp Response (*.tsr)", "tsr");
        chooser.setFileFilter(tsrFilter);
        if (chooser.showOpenDialog(panelValidador) == JFileChooser.APPROVE_OPTION) {
            try {
                byte[] response = Utils.readContent(chooser.getSelectedFile().getAbsolutePath());
                TimestampGenerator timestampGen = new TimestampGenerator();
                timestampGen.validate(response);
                textAreaValidacaoCarimboTempo.append(timestampGen.getTimestamp().toString());

                if (JOptionPane.showConfirmDialog(panelValidador, "Deseja efetuar a validação do hash do arquivo original?", "Mensagem", JOptionPane.YES_NO_OPTION) == 0) {
                    chooser.resetChoosableFileFilters();
                    if (chooser.showOpenDialog(panelValidador) == JFileChooser.APPROVE_OPTION) {
                        byte[] original = Utils.readContent(chooser.getSelectedFile().getAbsolutePath());
                        timestampGen.validate(response, original);
                        textAreaValidacaoCarimboTempo.append("\nO arquivo fornecido corresponde ao carimbo de tempo.");
                    } else {
                        JOptionPane.showMessageDialog(panelValidador, "A operacao foi cancelada pelo usuario.", "Mensagem", JOptionPane.INFORMATION_MESSAGE);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(panelValidador, e.getMessage(), "Mensagem", JOptionPane.ERROR_MESSAGE);
            } finally {
                buttonValidar.setEnabled(true);
                setCursor(null); //turn off the wait cursor
            }
        } else {
            JOptionPane.showMessageDialog(panelValidador, "A operacao foi cancelada pelo usuario.", "Mensagem", JOptionPane.INFORMATION_MESSAGE);
            buttonValidar.setEnabled(true);
            setCursor(null); //turn off the wait cursor
        }
    }//GEN-LAST:event_buttonValidarActionPerformed
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton buttonCarimbar;
    private javax.swing.JButton buttonValidar;
    private javax.swing.JFileChooser chooser;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel labelCertificadosDigitais;
    private javax.swing.JLabel labelRegistroEventos;
    private javax.swing.JPanel panelCarimbador;
    private javax.swing.JPanel panelValidador;
    private javax.swing.JScrollPane scrollPaneCertificados;
    private javax.swing.JScrollPane scrollPaneCertificados2;
    private javax.swing.JScrollPane scrollPaneInformacoes;
    private javax.swing.JTabbedPane tabbedPane;
    private javax.swing.JTable tableCertificados;
    private javax.swing.JTextArea textAreaRequisicaoCarimboTempo;
    private javax.swing.JTextArea textAreaValidacaoCarimboTempo;
    // End of variables declaration//GEN-END:variables
}
