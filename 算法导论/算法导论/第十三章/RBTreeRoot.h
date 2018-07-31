//
//  RBTreeRoot.h
//  算法导论
//
//  Created by 温杰 on 2018/5/22.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "RBTree.h"
@interface RBTreeRoot : NSObject
@property (nonatomic,strong) RBTree *root;
@property (nonatomic,strong) RBTree *guard;
@end
