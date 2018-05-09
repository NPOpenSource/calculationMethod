//
//  SelectionSort.m
//  算法导论
//
//  Created by 温杰 on 2018/5/9.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "SelectionSort.h"
#import "Util.h"

@implementation SelectionSort
+(void)selectionSort:(int*)A length:(int)length{
    NSLog(@"选择排序");
    NSLog(@"排序前数组：");
    printArr(A, length);
    for (int i =1; i < length; i++) {
        int key =A[i-1];
        int min = i-1;
        for (int j=i; j<length; j++) {
            if (A[j]<key) {
                key = A[j];
                min = j;
            }
        }
        exchange(&A[i-1], &A[min]);
    }
    NSLog(@"排序后数组：");
    printArr(A, length);
}
@end
