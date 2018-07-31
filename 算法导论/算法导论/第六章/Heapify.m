//
//  Heapify.m
//  算法导论
//
//  Created by 温杰 on 2018/5/11.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "Heapify.h"
#import "Util.h"
///构建堆排序 最大数应该在0 位置  而 0 位置没办法

int left(int index){
    return 2*index+1;
}

int right(int index){
    return 2*index+2;
}
int parent(int index){
    return (index-1)/2;
}

void Max_heapify(int *A,int index,int length){
    int l = left(index);
    int r = right(index);
    int largest=index;
    if (l<length && A[l]>A[index]) {
        largest =l;
    }
    if (r<length && A[r]>A[largest]) {
        largest = r;
    }
    if (largest!= index) {
        exchange(&A[index], &A[largest]);
        Max_heapify(A, largest, length);
    }
}

void buildMaxHeap(int *A,int length){
    for (int i=(length-1)/2; i>=0; i--) {
        Max_heapify(A, i, length);
    }
}
void heapSort(int *A,int length){
    buildMaxHeap(A, length);
    for (int i=length; i>=1; i--) {
        exchange(&A[0], &A[i-1]);
        Max_heapify(A, 0, i-1);
    }
}


#pragma mark - 队列优先级
///程序逆运算

int heapMaximum(int *A){
    return A[0];
}

int heapExtractMax(int *A,int length){
    if (length<1) {
        return -1;
    }
    int max = A[0];
    A[0]=A[length-1];
    Max_heapify(A, 0, length-1);
    return max;
}

void heapIncreaseKey(int * A,int i,int key){
    if (key<A[i]) {
        return ;
    }
    A[i]=key;
    
}

void maxHeapInsert(int *A,int key){
    
}

@interface Heapify ()
@property (nonatomic,assign) int * A;
@property (nonatomic,assign) int heapSize;
@property (nonatomic,assign) int mallocLength;

@end

@implementation Heapify

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.heapSize =0;
        self.mallocLength = 10;
        self.A = getMallocSize(self.mallocLength);
    }
    return self;
}
-(void)maxHeapInsert:(int) key{
    self.heapSize+=1;
    ///最小数
    self.A[self.heapSize-1]=-1;
    [self heapIncreaseKey:self.heapSize-1 :key];
    
}

-(void)heapIncreaseKey:(int)index :(int) key{
    if (key<self.A[index]) {
        NSLog(@"new key is smaller than crrent key");
        return;
    }
    self.A[index] = key;
    int i = index;
    while (i>0 && self.A[parent(i)]<self.A[i]) {
        exchange(&self.A[parent(i)], &self.A[i]);
        i = parent(i);
    }
}

-(int )heapExtractMax{
    if (self.heapSize<=0) {
        return -1;
    }
    int max = self.A[0];
    self.A[0]=self.A[self.heapSize-1];
    self.heapSize -=1;
    Max_heapify(self.A, 0, self.heapSize);
    return max;
}

-(int)heapMaxImum{
    return self.A[0];
}

-(void)print{
    printArr(self.A, self.heapSize);
}

@end
