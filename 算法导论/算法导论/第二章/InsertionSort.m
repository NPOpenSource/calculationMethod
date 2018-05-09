//
//  InsertionSort.m
//  算法导论
//
//  Created by 温杰 on 2018/5/9.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "InsertionSort.h"
#import "Util.h"
#import "BinarySearch.h"
@implementation InsertionSort
/*
///时间复杂度
折半插入排序适合记录数较多的场景，与直接插入排序相比，折半插入排序在寻找插入位置上面所花的时间大大减少，但是折半插入排序在记录移动次数方面和直接插入排序是一样的，所以其时间复杂度为O(n2)
。
其次，折半插入排序的记录比较次数与初始序列无关。因为每趟排序折半寻找插入位置时，折半次数是一定的，折半一次就要比较一次，所以比较次数也是一定的。
 */
+(void)insertionSortBinarySearch:(int *)A length:(int)length{
    NSLog(@"插入二分法排序");
    NSLog(@"排序前数组：");
    printArr(A, length);
    for (int j=1; j<length; j++) {
        int key = A[j];
        int i = j-1;
        
      int m=  binarySearchLessSortArr(A, 0, i+1, key);
         NSLog(@"%d",key);
        printArr(A, i+1);
        NSLog(@" %d",m);
        for (int k=i; k>m; k--) {
            A[k+1]=A[k];
        }
        
//        while (i>=0 && A[i]>key) {
//            A[i+1]=A[i];
//            i -= 1;
//        }
        A[m+1]=key;
    }
    NSLog(@"排序后数组：");
    printArr(A, length);
}

+(void)insertionSort:(int *)A length:(int)length{
    NSLog(@"插入排序");
    NSLog(@"排序前数组：");
    printArr(A, length);
    for (int j=1; j<length; j++) {
        int key = A[j];
        int i = j-1;
        while (i>=0 && A[i]>key) {
            A[i+1]=A[i];
            i -= 1;
        }
        A[i+1]=key;
    }
    NSLog(@"排序后数组：");
    printArr(A, length);
}

+(void)insertionSortAscendingOrder:(int *)A length:(int)length{
    NSLog(@"插入排序升序排列");
    NSLog(@"排序前数组：");
    printArr(A, length);
    for (int j=1; j<length; j++) {
        int key = A[j];
        int i = j-1;
        while (i>=0 && A[i]<key) {
            A[i+1]=A[i];
            i -= 1;
        }
        A[i+1]=key;
    }
    NSLog(@"排序后数组：");
    printArr(A, length);
}
+(void)insertionRecursionSort:(int *)A length:(int)length{
    if (length>1) {
        [self insertionRecursionSort:A length:length-1];
    }
    int last = A[length-1];
    int i=length-2;
    while (i>=0&&A[i]>last) {
        A[i+1]=A[i];
        i-=1;
    }
    A[i+1]=last;
    printArr(A, length);
}



@end
