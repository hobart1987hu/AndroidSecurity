package security.score;

import android.content.Context;

/**
 * Created by huzeyin on 2017/8/26.
 */

public class SCore {

    private static Context mSContext;

    public static void init(Context context) {
        mSContext = context;
    }

    public static Context getContext() {
        return mSContext;
    }

}
