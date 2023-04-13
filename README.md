TEST.java文件代码如下：
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;


public class Test extends JFrame {
    public static final int WIDTH = 550;
    public static final int HEIGHT = 200;

    public static void main(String args[]) {
        Test fe = new Test();
        fe.show();
    }

    Test() {
        this.setSize(WIDTH, HEIGHT);
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setResizable(false);
        Toolkit tk = Toolkit.getDefaultToolkit();
        Dimension screenSize = tk.getScreenSize();
        this.setLocation((screenSize.width - WIDTH) / 2,
                (screenSize.height - HEIGHT) / 2);
        this.setTitle("文件加密器(TriDES)");
        Container c = this.getContentPane();
        c.setLayout(new FlowLayout());

        final FilePanel fp = new FilePanel("文件选择");
        c.add(fp);

        final KeyPanel pp = new KeyPanel("密码");
        c.add(pp);

        JButton jbE = new JButton("加密");
        c.add(jbE);
        jbE.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                File file = new File(fp.getFileName());
                if (file.exists())
                    encrypt(file.getAbsoluteFile(), pp.getKey());
                else
                    JOptionPane.showMessageDialog(null, "请选择文件！", "提示",
                            JOptionPane.OK_OPTION);
            }
        });
        JButton jbD = new JButton("解密");
        c.add(jbD);
        jbD.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                File file = new File(fp.getFileName());
                if (file.exists())
                    decrypt(file.getAbsoluteFile(), pp.getKey());
                else
                    JOptionPane.showMessageDialog(null, "请选择文件！", "提示",
                            JOptionPane.OK_OPTION);
            }
        });
    }

    /**
     * 加密函数 输入： 要加密的文件，密码（由0-F组成，共48个字符，表示3个8位的密码）如：
     * AD67EA2F3BE6E5ADD368DFE03120B5DF92A8FD8FEC2F0746 其中： AD67EA2F3BE6E5AD
     * DES密码一 D368DFE03120B5DF DES密码二 92A8FD8FEC2F0746 DES密码三 输出：
     * 对输入的文件加密后，保存到同一文件夹下增加了".tdes"扩展名的文件中。
     */
    private void encrypt(File fileIn, String sKey) {
        try {
            if (sKey.length() == 48) {
                byte[] bytK1 = getKeyByStr(sKey.substring(0, 16));
                byte[] bytK2 = getKeyByStr(sKey.substring(16, 32));
                byte[] bytK3 = getKeyByStr(sKey.substring(32, 48));

                FileInputStream fis = new FileInputStream(fileIn);
                byte[] bytIn = new byte[(int) fileIn.length()];
                for (int i = 0; i < fileIn.length(); i++) {
                    bytIn[i] = (byte) fis.read();
                }
                // 加密
                byte[] bytOut = encryptByDES(
                        encryptByDES(encryptByDES(bytIn, bytK1), bytK2), bytK3);
                String fileOut = fileIn.getPath() + ".tdes";
                FileOutputStream fos = new FileOutputStream(fileOut);
                for (int i = 0; i < bytOut.length; i++) {
                    fos.write((int) bytOut[i]);
                }
                fos.close();
                JOptionPane.showMessageDialog(this, "加密成功！", "提示",
                        JOptionPane.OK_OPTION);
            } else
                JOptionPane.showMessageDialog(this, "密码长度必须等于48！", "错误信息",
                        JOptionPane.ERROR_MESSAGE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 解密函数 输入： 要解密的文件，密码（由0-F组成，共48个字符，表示3个8位的密码）如：
     * AD67EA2F3BE6E5ADD368DFE03120B5DF92A8FD8FEC2F0746 其中： AD67EA2F3BE6E5AD
     * DES密码一 D368DFE03120B5DF DES密码二 92A8FD8FEC2F0746 DES密码三 输出：
     * 对输入的文件解密后，保存到用户指定的文件中。
     */
    private void decrypt(File fileIn, String sKey) {
        try {
            if (sKey.length() == 48) {
                String strPath = fileIn.getPath();
                if (strPath.substring(strPath.length() - 5).toLowerCase()
                        .equals(".tdes"))
                    strPath = strPath.substring(0, strPath.length() - 5);
                else {
                    JOptionPane.showMessageDialog(this, "不是合法的加密文件！", "提示",
                            JOptionPane.OK_OPTION);
                    return;
                }
                JFileChooser chooser = new JFileChooser();
                chooser.setCurrentDirectory(new File("."));
                chooser.setSelectedFile(new File(strPath));
                // 用户指定要保存的文件
                int ret = chooser.showSaveDialog(this);
                if (ret == JFileChooser.APPROVE_OPTION) {  //常量，确定用户是否点击了确定或保存

                    byte[] bytK1 = getKeyByStr(sKey.substring(0, 16));
                    byte[] bytK2 = getKeyByStr(sKey.substring(16, 32));
                    byte[] bytK3 = getKeyByStr(sKey.substring(32, 48));

                    FileInputStream fis = new FileInputStream(fileIn);
                    byte[] bytIn = new byte[(int) fileIn.length()];
                    for (int i = 0; i < fileIn.length(); i++) {
                        bytIn[i] = (byte) fis.read();
                    }
                    // 解密
                    byte[] bytOut = decryptByDES(
                            decryptByDES(decryptByDES(bytIn, bytK3), bytK2),
                            bytK1);
                    File fileOut = chooser.getSelectedFile();
                    fileOut.createNewFile();
                    FileOutputStream fos = new FileOutputStream(fileOut);
                    for (int i = 0; i < bytOut.length; i++) {
                        fos.write((int) bytOut[i]);
                    }
                    fos.close();
                    JOptionPane.showMessageDialog(this, "解密成功！", "提示",
                            JOptionPane.OK_OPTION);
                }
            } else
                JOptionPane.showMessageDialog(this, "密码长度必须等于48！", "错误信息",
                        JOptionPane.ERROR_MESSAGE);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(this, "解密失败，请核对密码！", "提示",
                    JOptionPane.OK_OPTION);
        }
    }

    /**
     * 用DES方法加密输入的字节 bytKey需为8字节长，是加密的密码
     */
    private byte[] encryptByDES(byte[] bytP, byte[] bytKey) throws Exception {
        DESKeySpec desKS = new DESKeySpec(bytKey);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey sk = skf.generateSecret(desKS);
        Cipher cip = Cipher.getInstance("DES");
        cip.init(Cipher.ENCRYPT_MODE, sk);
        return cip.doFinal(bytP);
    }


    private byte[] decryptByDES(byte[] bytE, byte[] bytKey) throws Exception {
        DESKeySpec desKS = new DESKeySpec(bytKey);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("DES");
        SecretKey sk = skf.generateSecret(desKS);
        Cipher cip = Cipher.getInstance("DES");
        cip.init(Cipher.DECRYPT_MODE, sk);
        return cip.doFinal(bytE);
    }

    /**
     * 输入密码的字符形式，返回字节数组形式。 如输入字符串：AD67EA2F3BE6E5AD 返回字节数组：{
     * 173,103,234,47,59,230,229,173 }
     */
    private byte[] getKeyByStr(String str) {
        byte[] bRet = new byte[str.length() / 2];
        for (int i = 0; i < str.length() / 2; i++) {
            Integer itg = new Integer(16 * getChrInt(str.charAt(2 * i))
                    + getChrInt(str.charAt(2 * i + 1)));
            bRet[i] = itg.byteValue();
        }
        return bRet;
    }

    /**
     * 计算一个16进制字符的10进制值 输入：0-F
     */
    private int getChrInt(char chr) {
        int iRet = 0;
        if (chr == "0".charAt(0))
            iRet = 0;
        if (chr == "1".charAt(0))
            iRet = 1;
        if (chr == "2".charAt(0))
            iRet = 2;
        if (chr == "3".charAt(0))
            iRet = 3;
        if (chr == "4".charAt(0))
            iRet = 4;
        if (chr == "5".charAt(0))
            iRet = 5;
        if (chr == "6".charAt(0))
            iRet = 6;
        if (chr == "7".charAt(0))
            iRet = 7;
        if (chr == "8".charAt(0))
            iRet = 8;
        if (chr == "9".charAt(0))
            iRet = 9;
        if (chr == "A".charAt(0))
            iRet = 10;
        if (chr == "B".charAt(0))
            iRet = 11;
        if (chr == "C".charAt(0))
            iRet = 12;
        if (chr == "D".charAt(0))
            iRet = 13;
        if (chr == "E".charAt(0))
            iRet = 14;
        if (chr == "F".charAt(0))
            iRet = 15;
        return iRet;
    }
}

KeyPanel.java文件代码如下：

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.security.*;
import javax.crypto.*;

/**
 * 密码生成组件。
 */
class KeyPanel extends JPanel {
    KeyPanel(String str) {
        JLabel label = new JLabel(str);
        JTextField fileText = new JTextField(35);
        JButton chooseButton = new JButton("随机产生");
        this.add(label);
        this.add(fileText);
        this.add(chooseButton);
        clickAction ca = new clickAction(this);
        chooseButton.addActionListener(ca);

    }

    // 返回生成的密码（48个字符长度）
    public String getKey() {
        JTextField jtf = (JTextField) this.getComponent(1);
        return jtf.getText();
    }

    private class clickAction implements ActionListener {
        clickAction(Component c) {
            cmpt = c;
        }

        public void actionPerformed(ActionEvent event) {
            try {
                KeyGenerator kg = KeyGenerator.getInstance("DES");
                kg.init(56);
                Key ke = kg.generateKey();
                byte[] bytK1 = ke.getEncoded();
                ke = kg.generateKey();
                byte[] bytK2 = ke.getEncoded();
                ke = kg.generateKey();
                byte[] bytK3 = ke.getEncoded();

                JPanel jp = (JPanel) cmpt;
                JTextField jtf = (JTextField) jp.getComponent(1);
                jtf.setText(getByteStr(bytK1) + getByteStr(bytK2)
                        + getByteStr(bytK3));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private String getByteStr(byte[] byt) {
            String strRet = "";
            for (int i = 0; i < byt.length; i++) {
                // System.out.println(byt[i]);
                strRet += getHexValue((byt[i] & 240) / 16);
                strRet += getHexValue(byt[i] & 15);
            }
            return strRet;
        }

        private String getHexValue(int s) {
            String sRet = null;
            switch (s) {
                case 0:
                    sRet = "0";
                    break;
                case 1:
                    sRet = "1";
                    break;
                case 2:
                    sRet = "2";
                    break;
                case 3:
                    sRet = "3";
                    break;
                case 4:
                    sRet = "4";
                    break;
                case 5:
                    sRet = "5";
                    break;
                case 6:
                    sRet = "6";
                    break;
                case 7:
                    sRet = "7";
                    break;
                case 8:
                    sRet = "8";
                    break;
                case 9:
                    sRet = "9";
                    break;
                case 10:
                    sRet = "A";
                    break;
                case 11:
                    sRet = "B";
                    break;
                case 12:
                    sRet = "C";
                    break;
                case 13:
                    sRet = "D";
                    break;
                case 14:
                    sRet = "E";
                    break;
                case 15:
                    sRet = "F";
            }
            return sRet;
        }

        private Component cmpt;
    }
}

FilePanel.java文件代码如下：
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


这是第二个加密算法代码：

public class DES {
    private static final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };
    //IP逆置换
    private static final int[] IPReverse = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25};
    // E位选择表(扩展置换表)
    private static final int[] E = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1};
    //P换位表(单纯换位表)
    private static final int[] P = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25};
    //PC1
    private static final int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4};
    // PC2
    private static final int[] PC2 = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32};
    // SBox
    private static final int[][] SBox = {
            // S1
            {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                    0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                    4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                    15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
            // S2
            {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                    3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                    0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                    13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
            // S3
            {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                    13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                    13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                    1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
            // S4
            {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                    13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                    10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                    3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
            // S5
            {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                    14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                    4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                    11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
            // S6
            {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                    10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                    9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                    4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
            // S7
            {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                    13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                    1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                    6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
            // S8
            {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                    1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                    7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                    2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

    private static final int BLOCK_SIZE = 8; // 块大小为 8 字节

    // 生成 16 个子密钥
    private static byte[][] generateSubkeys(byte[] key) {
        byte[][] subkeys = new byte[16][];
        // 初始置换（PC1 置换）
        byte[] keyBits = new byte[56];
        for (int i = 0; i < 56; i++) {
            keyBits[i] = key[PC1[i] - 1];
        }
        // 生成 16 个子密钥
        for (int i = 0; i < 16; i++) {
            // 左移
            byte[] left = new byte[28];
            byte[] right = new byte[28];
            System.arraycopy(keyBits, 0, left, 0, 28);
            System.arraycopy(keyBits, 28, right, 0, 28);
            int shift = SHIFT[i];
            for (int j = 0; j < 28; j++) {
                int index = (j + shift) % 28;
                keyBits[j] = left[index];
                keyBits[j + 28] = right[index];
            }
            // 选择置换（PC2 置换）
            byte[] subkey = new byte[48];
            for (int j = 0; j < 48; j++) {
                subkey[j] = keyBits[PC2[j] - 1];
            }
            subkeys[i] = subkey;
        }
        return subkeys;
    }

    // IP 置换
    private static byte[] permuteInitial(byte[] input) {
        byte[] output = new byte[64];
        for (int i = 0; i < 64; i++) {
            output[i] = input[IP[i] - 1];
        }
        return output;
    }

    // IP 逆置换
    private static byte[] permuteFinal(byte[] input) {
        byte[] output = new byte[64];
        for (int i = 0; i < 64; i++) {
            output[i] = input[IPReverse[i] - 1];
        }
        return output;
    }

    // 拓展置位
    private static byte[] expand(byte[] input) {
        byte[] output = new byte[48];
        for (int i = 0; i < 48; i++) {
            output[i] = input[E[i] - 1];
        }
        return output;
    }

    // S 盒替代
    private static byte[] substitute(byte[] input) {
        byte[] output = new byte[32];
        for (int i = 0; i < 8; i++) {
            int row = (input[i * 6] << 1) + input[i * 6 + 5];
            int col = (input[i * 6 + 1] << 3) + (input[i * 6 + 2] << 2)
                    + (input[i * 6 + 3] << 1) + input[i * 6 + 4]; int val = S_BOX[i][row][col];
            // 将 val 转成二进制并拼接到 output 中
            for (int j = 0; j < 4; j++){output[i * 4 + 3 - j] = (byte) ((val >> j) & 0x01); } }
        return output; }

    // P 置换
    private static byte[] permute(byte[] input) {
        byte[] output = new byte[32];
        for (int i = 0; i < 32; i++) {
            output[i] = input[P[i] - 1];
        }
        return output;
    }

    // 生成 MAC
    public static byte[] generateMAC(byte[] message, byte[] key) {
        // 1. 将 key 生成 16 个子密钥
        byte[][] subkeys = generateSubkeys(key);

        // 2. 初始化 IV 为 0
        byte[] iv = new byte[8];

        // 3. 分组
        byte[][] blocks = divideIntoBlocks(message, iv);

        // 4. 对每个分组进行加密
        byte[] result = new byte[8];
        for (byte[] block : blocks) {
            result = encryptBlock(block, subkeys);
        }

        // 5. 返回最后一个分组的加密结果作为 MAC
        return result;
    }

    // 对单个块进行加密
    private static byte[] encryptBlock(byte[] block, byte[][] subkeys) {
        // 1. 初始置换（IP 置换）
        byte[] permutedBlock = permuteInitial(block);

        // 2. 分割 permutedBlock 为左右两半
        byte[] left = new byte[32];
        byte[] right = new byte[32];
        System.arraycopy(permutedBlock, 0, left, 0, 32);
        System.arraycopy(permutedBlock, 32, right, 0, 32);

        // 3. 循环加密
        for (int i = 0; i < 16; i++) {
            // 计算 F 函数的结果
            byte[] expandedRight = expand(right); // 拓展置位
            byte[] subkey = subkeys[i]; // 获取子密钥
            byte[] xorResult = xor(expandedRight, subkey); // 异或
            byte[] substitutedResult = substitute(xorResult); // S 盒替代
            byte[] permutedResult = permute(substitutedResult); // P 置换

            // 计算下一轮迭代所需的左右两部分
            byte[] newLeft = right;
            byte[] newRight = xor(left, permutedResult);
            left = newLeft;
            right = newRight;
        }

        // 4. 合并左右两部分并进行 IP 逆置换
        byte[] combined = new byte[64];
        System.arraycopy(right, 0, combined, 0, 32);
        System.arraycopy(left, 0,combined, 32, 32);
        combined = permuteInverse(combined); // IP-1 逆置换
        // 5. 返回加密结果
        return combined;
    }
    // IP 初始置换逆置换
    private static byte[] permuteInverse(byte[] input) { byte[] output = new byte[64];
        for (int i = 0; i < 64; i++) { output[i] = input[IPInverse[i] - 1]; }
        return output; }

    byte[] key = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
    DES des = new DES(key);

    byte[] message = "Hello, world!".getBytes();
    byte[] mac = des.generateMAC(message);
    public static void main(String args[]) {
        byte[] key = { 0x12, 0x34, 0x56, 0x78, (byte) 0x90, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF };
        DES des = new DES(key);
        byte[] message = "Hello, world!".getBytes();
        byte[] mac = des.generateMAC(message);}
    }
