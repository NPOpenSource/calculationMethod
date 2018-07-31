//
//  RadixSort.m
//  算法导论
//
//  Created by 温杰 on 2018/5/17.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "RadixSort.h"
#import "Util.h"

///需要个二维数组10*length
void radixSort(int *A,int d,int length){
    RadixSort *radixSort[10];
    for (int i =0; i<10; i++) {
        radixSort[i]=[[RadixSort alloc]initWithLength:length];
    }
    
    for (int i = 0; i< d; i++) {
        for (int j =0; j<length; j++) {
            int num =  A[j];
            for (int t=0; t<i; t++) {
                  num = num/10;
            }
            num = num%10;
            [radixSort[num] append:A[j]];
        }
        int begin = 0;
        int length =0;
        for (int m=0; m<10; m++) {
            [radixSort[m] writeData:A beginLocation:begin length:&length];;
            begin+=length;
            [radixSort[m] clear];
        }
        
    }
    
}

///基于计数排序，
void radixSortBasecountingSort(int *A,int d,int length){
    int * B = getMallocSize(length);
    int k[10]={0};
    
    for (int i = 0; i< d; i++){
        for (int j =0; j<length; j++) {
            int num =  A[j];
            for (int t=0; t<i; t++) {
                num = num/10;
            }
            num = num%10;
            k[num]+=1;
        }
        
        for (int i=1; i<10; i++) {
            k[i]+=k[i-1];
        }
        
        ///顺序问题
        for (int j =length-1; j>=0; j--) {
            int num =  A[j];
            for (int t=0; t<i; t++) {
                num = num/10;
            }
            ///矫正
            num = num%10;
            B[k[num]-1]=A[j];
            k[num]-=1;
        }
        printArr(B, length);

        for (int j =0; j<length; j++) {
            A[j]=B[j];
        }
        for (int m=0; m<10; m++) {
            k[m]=0;
        }
       
        
    }
    
    
    
}


@interface RadixSort()
@property (nonatomic ,assign) int * A;
@property (nonatomic ,assign) int index;
@property (nonatomic ,assign) int length;

@end

@implementation RadixSort
- (instancetype)initWithLength:(int)length
{
    self = [super init];
    if (self) {
        self.index   = 0;
        self.length = length;
        self.A=getMallocSize(length);
    }
    return self;
}

-(void)append:(int)num{
    self.A[self.index]= num;
    self.index++;
}
-(void)clear{
    memset(self.A, 0, self.length);
    self.index = 0;
}

-(void)writeData:(int *)m beginLocation:(int)beginIndex length:(int *)length{
    for (int i=0; i<self.index; i++) {
        m[beginIndex+i]=self.A[i];
    }
    *length = self.index;
}

@end
