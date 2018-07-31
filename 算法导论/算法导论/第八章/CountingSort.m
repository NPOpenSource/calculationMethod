//
//  CountingSort.m
//  算法导论
//
//  Created by 温杰 on 2018/5/17.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "CountingSort.h"
#import "Util.h"
void countingSort(int *A,int*B,int k ,int length){
    int * c = getMallocSize(k+1);
    for (int i =0; i<=k; i++) {
        c[i]=0;
    }
    
    for (int j =0; j<length; j++) {
        c[A[j]]+=1;
    }
    
    for (int i=1; i<=k; i++) {
        c[i]+=c[i-1];
    }
    
    for (int j=length-1; j>=0; j--) {
        B[c[A[j]]-1]=A[j];
        c[A[j]]-=1;
    }
    
}

@implementation CountingSort

@end
