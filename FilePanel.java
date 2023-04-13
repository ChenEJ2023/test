import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.io.*;
class FilePanel extends JPanel {
    FilePanel(String str) {
        JLabel label = new JLabel(str);
        JTextField fileText = new JTextField(35);
        JButton chooseButton = new JButton("浏览...");
        this.add(label);
        this.add(fileText);
        this.add(chooseButton);
        clickAction ca = new clickAction(this);
        chooseButton.addActionListener(ca);

    }

    public String getFileName() {
        JTextField jtf = (JTextField) this.getComponent(1);
        return jtf.getText();
    }

    private class clickAction implements ActionListener {
        clickAction(Component c) {
            cmpt = c;
        }

        public void actionPerformed(ActionEvent event) {
            JFileChooser chooser = new JFileChooser();
            chooser.setCurrentDirectory(new File("."));
            int ret = chooser.showOpenDialog(cmpt);
            if (ret == JFileChooser.APPROVE_OPTION) {
                JPanel jp = (JPanel) cmpt;
                JTextField jtf = (JTextField) jp.getComponent(1);
                jtf.setText(chooser.getSelectedFile().getPath());
            }
        }

        private Component cmpt;
    }
}
