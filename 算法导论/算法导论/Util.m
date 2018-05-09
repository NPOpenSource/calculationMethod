//
//  Util.m
//  算法导论
//
//  Created by 温杰 on 2018/5/9.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "Util.h"

@implementation Util
void printArr(int *arr,int length){
    NSMutableString * str = [NSMutableString new];
    for (int i=0; i<length; i++) {
        [str appendFormat:@"%d,",arr[i]];
    }
    NSLog(@"%@",str);
}
void printArrIndex(int *arr,int begin,int end){
    NSMutableString * str = [NSMutableString new];
    for (int i=begin; i<=end; i++) {
        [str appendFormat:@"%d,",arr[i]];
    }
    NSLog(@"%@",str);
}


int* getMallocRandomNum(int length,int max){
    if (max<=0) {
        return NULL;
    }
    int * m = malloc(sizeof(int)*length);
    for (int i=0; i<length; i++) {
        m[i]=  (int)random()%max;
    }
    return m;
}

void exchange(int* A,int * B){
    int a= *A;
    int b= *B;
    int middle = 0;
    middle =*A;
    *A= *B;
    *B = middle;
    
}
@end
