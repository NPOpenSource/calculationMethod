//
//  Bubblesort.m
//  算法导论
//
//  Created by 温杰 on 2018/5/10.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "Bubblesort.h"
#import "Util.h"
///递增排列
void bubbleSort(int *A ,int length){
    NSLog(@"冒泡排序");
    NSLog(@"排序前数组：");
    printArr(A, length);
    for (int i=0; i<length; i++) {
        for (int j=length-1; j>i; j--) {
            if (A[j-1]>A[j]) {
                exchange(&A[j-1], &A[j]);
            }
        }
    }
    NSLog(@"排序后数组：");
    printArr(A, length);
}


@implementation Bubblesort

@end
