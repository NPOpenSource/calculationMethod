//
//  InsertionSort.h
//  算法导论
//
//  Created by 温杰 on 2018/5/9.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface InsertionSort : NSObject
+(void)insertionSortBinarySearch:(int *)A length:(int)length;
+(void)insertionSort:(int *)A length:(int)length;
+(void)insertionSortAscendingOrder:(int *)A length:(int)length;
+(void)insertionRecursionSort:(int *)A length:(int)length;
@end
