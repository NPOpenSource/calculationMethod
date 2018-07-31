//
//  QuickSort.m
//  算法导论
//
//  Created by 温杰 on 2018/5/16.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "QuickSort.h"
#import "Util.h"
int partition(int *A,int p,int r){
    int x = A[r];
    int i = p-1;
    for (int j=p; j<r; j++) {
        if (A[j]<=x) {
            i+=1;
            exchange(&A[i], &A[j]);
        }
    }
    exchange(&A[i+1], &A[r]);
    return i+1;
}

void cquickSort(int *A,int p ,int r){
    if (p<r) {
        int q = partition(A, p, r);
        cquickSort(A, p, q-1);
        cquickSort(A, q+1, r);

    }
}

int randomizedPartition(int *A,int p,int r){
    int i = randomNum(p, r);
    exchange(&A[i], &A[r]);
    return partition(A, p, r);
}

void randomizedQuickSort(int *A,int p,int r){
    if (p<r) {
        int q = randomizedPartition(A, p, r);
        randomizedQuickSort(A, p, q-1);
        randomizedQuickSort(A, q+1, r);
    }
}




@implementation QuickSort

@end
