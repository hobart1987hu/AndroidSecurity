package com.android.security;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.util.Objects;
import java.util.Random;

import security.score.Security;

public class MainActivity extends Activity {

    private static final String TAG = "Security";
    private Random random;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        random = new Random();
        findViewById(R.id.aesEncode).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startEncode();
            }
        });
        findViewById(R.id.md5Encode).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startMD5();
            }
        });
    }

    private void startMD5() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                while (!stop) {
                    String data = "11" + random.nextInt() + random.nextDouble() + random.nextLong() + "123";
                    String md5EncodeValue = Security.md5(data);
                    Log.d(TAG, "md5EncodeValue->:" + md5EncodeValue);

                    try {
                        Thread.sleep(1 * 1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }).start();

    }


    String key16 = "11qq22ww33ee44rr";
    String key24 = "11qq22ww33ee44rr55tt66yy";
    String key32 = "11qq22ww33ee44rr55tt66yy77uu88ii";

    private void startEncode() {
        if (stop) return;
        final String data = "11" + random.nextInt() + random.nextDouble() + random.nextLong() + "22";
        Log.d(TAG, "encode data:" + data);
        final String encrypt = Security.AESEncryptWithKey(key32, data);
        Log.d(TAG, "encrypt -> " + encrypt);

        Message msg = new Message();
        msg.what = 1;
        String[] value = new String[]{data, encrypt};
        msg.obj = value;
        mHandler.sendMessage(msg);
    }

    int successCount = 0;

    private Handler mHandler = new Handler() {
        /**
         * @param msg
         */
        @Override
        public void handleMessage(Message msg) {
            super.handleMessage(msg);
            if (stop) return;
            if (msg.what == 1) {
                String[] value = (String[]) msg.obj;
                String originalValue = value[0];
                String encrypt = value[1];
                final String decrypt = Security.AESDecryptWithKey(key32, encrypt);
                Log.d(TAG, "decrypt ->" + decrypt);
                if (TextUtils.equals(originalValue, decrypt)) {
                    Log.d(TAG, "----encrypt success---- successCount->" + (++successCount));
                }
                mHandler.sendEmptyMessageDelayed(2, 2 * 1000);
            } else if (msg.what == 2) {
                startEncode();
            }
        }
    };
    boolean stop = false;

    @Override
    protected void onDestroy() {
        stop = true;
        super.onDestroy();
    }

    public void checkSignature(View view) {
        final int result = Security.verifySign();
        if (result > 0) {
            showToast("signature is correct");
        } else {
            showToast("signature is wrong");
        }
    }

    void showToast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_LONG).show();
    }
}
