//
//  Util.h
//  算法导论
//
//  Created by 温杰 on 2018/5/9.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Util : NSObject
void printArr(int *arr,int length);
void printArrIndex(int *arr,int begin,int end);
void exchange(int* A,int * B);

int* getMallocRandomNum(int length,int max);

@end
