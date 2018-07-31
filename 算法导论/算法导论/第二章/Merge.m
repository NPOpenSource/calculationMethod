//
//  Merge.m
//  算法导论
//
//  Created by 温杰 on 2018/5/9.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "Merge.h"
#import "Util.h"


void mergeSort(int *A,int begin,int end){
    if (begin<end) {
        int q = (end+begin)/2;
        mergeSort(A, begin, q);
        mergeSort(A, q+1, end);
        merge(A, begin, q, end);
    }
    
}



void merge(int * A ,int begin,int middle,int end){
    NSLog(@"merge两个顺序数组");
    NSLog(@"排序前数组：");
    printArrIndex(A, begin, end);
    
    int n1 = middle-begin+1;
    int n2 = end -middle;
    int * L=malloc(sizeof(int)*(n1+1));
    memset(L, 0, n1+1);
    for (int i=0; i<n1; i++) {
        L[i]=A[begin+i];
    }

    int * R=malloc(sizeof(int)*(n2+1));;
    memset(R, 0, n2+1);
    for (int i=0; i<n2; i++) {
        R[i]=A[middle+i+1];
    }
    L[n1]=INT_MAX;
    R[n2]=INT_MAX;
    int i = 0;
    int j = 0;
    for (int k=begin ; k<=end; k++) {
        if (L[i]<R[j]) {
            A[k]=L[i];
            i+=1;
        }else{
            A[k]=R[j];
            j+=1;
        }
    }
  

    free(L);
    free(R);
    NSLog(@"排序后数组：");
    printArrIndex(A, begin, end);
}


///求解逆序对
void mergeReverseOrderPair(int * A ,int begin,int middle,int end,int *num){
    NSLog(@"merge两个顺序数组");
    NSLog(@"排序前数组：");
    printArrIndex(A, begin, end);
    
    int n1 = middle-begin+1;
    int n2 = end -middle;
    int * L=malloc(sizeof(int)*(n1+1));
    memset(L, 0, n1+1);
    for (int i=0; i<n1; i++) {
        L[i]=A[begin+i];
    }
    
    int * R=malloc(sizeof(int)*(n2+1));;
    memset(R, 0, n2+1);
    for (int i=0; i<n2; i++) {
        R[i]=A[middle+i+1];
    }
    L[n1]=INT_MAX;
    R[n2]=INT_MAX;
    int i = 0;
    int j = 0;
    for (int k=begin ; k<=end; k++) {
        
        if (L[i]<=R[j]) {
//            *num+=j;
            A[k]=L[i];
            i+=1;
        }else{
            *num+=n1-i;
            A[k]=R[j];
            j+=1;
        }
    }
    free(L);
    free(R);
    NSLog(@"排序后数组：");
    printArrIndex(A, begin, end);
}

void mergeSortReverseOrderPair(int *A,int begin,int end,int * num){
    if (begin<end) {
        int q = (end+begin)/2;
        mergeSortReverseOrderPair(A, begin, q,num);
        mergeSortReverseOrderPair(A, q+1, end,num);
        mergeReverseOrderPair(A, begin, q, end,num);
    }
}


@implementation Merge

@end
