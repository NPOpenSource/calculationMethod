//
//  main.m
//  算法导论
//
//  Created by 温杰 on 2018/5/9.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Util.h"
#import "InsertionSort.h"
#import "SelectionSort.h"
#import "Merge.h"
#import "BinarySearch.h"
int main(int argc, const char * argv[]) {
    NSLog(@"第二章");
    //插入排序
    int length = 10;
    int * A = getMallocRandomNum(length, 1000);
    printArr(A, length);
//    mergeSort(A, 0, length-1);
    [InsertionSort insertionSortBinarySearch:A length:length];
//    [InsertionSort insertionSort:A length:length];
//    [InsertionSort insertionSortAscendingOrder:A length:length];
//    [SelectionSort selectionSort:A length:length];
//    [InsertionSort insertionRecursionSort:A length:length];
//   binarySearchEqualSortArr(A, 0, length-1, 11);
   
//    int B[7]={1,2,3,5,2,4,6};
//    merge(B, 1, 3, 4);
    
    return 0;
}
