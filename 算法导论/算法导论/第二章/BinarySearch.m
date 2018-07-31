//
//  BinarySearch.m
//  算法导论
//
//  Created by 温杰 on 2018/5/9.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "BinarySearch.h"
int binarySearchLessSortArr(int* A,int begin ,int end,int searchNum){
    int result = 0;
    int middle = (begin+end)/2;
    if (middle==begin) {
        if (A[begin]>searchNum) {
            return begin-1;
        }
        if (A[end]<searchNum) {
            return end;
        }
        return begin;
    }
    if (A[middle]==searchNum) {
        result = middle;
    }else if (A[middle]>searchNum) {
      result= binarySearchLessSortArr(A, begin, middle, searchNum);
    }else{
        result = binarySearchLessSortArr(A, middle, end, searchNum);
    }
    return result;
    
}

///数组要求从小到大排列
int binarySearchEqualSortArr(int* A,int begin ,int end,int searchNum){
    int result = -1;
    int middle = (begin+end)/2;
    ///说明递归结束了
    if (middle==begin) {
        if (A[begin]==searchNum) {
            result= begin;
        }
        if (A[end]==searchNum) {
            result= end;
        }
        NSLog(@"二分法数据所在index %d",result);
        return result;
    }
    if (A[middle]==searchNum){
        result= middle;
    }else if (A[middle]==searchNum){
        result=   binarySearchEqualSortArr(A, middle, end, searchNum);
    }else{
       result =  binarySearchEqualSortArr(A, begin, middle, searchNum);
    }
    NSLog(@"二分法数据所在index %d",result);
    return result;
    
}




@implementation BinarySearch



@end
