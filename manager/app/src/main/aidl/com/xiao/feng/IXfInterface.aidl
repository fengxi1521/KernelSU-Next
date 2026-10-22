// IXfInterface.aidl
package com.xiao.feng;

import android.content.pm.PackageInfo;
import rikka.parcelablelist.ParcelableListSlice;

interface IXfInterface {
    ParcelableListSlice<PackageInfo> getPackages(int flags);
}